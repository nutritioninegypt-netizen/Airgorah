use crate::globals::*;
use airgorah_common::deps;
use airgorah_common::types::MacMode;
use std::process::Command;

/// Path to the macOS `airport` utility (in a PrivateFrameworks bundle).
#[cfg(target_os = "macos")]
pub const AIRPORT_PATH: &str = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

#[derive(thiserror::Error, Debug)]
pub enum IfaceError {
    #[error("Input/Output error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Utf8 conversion error")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Interface '{0}' could not be found")]
    IfaceNotFound(String),

    #[error("Could not change MAC address: interface not in monitor mode")]
    IfaceNotMonitor,

    #[error("MAC address is invalid: change its value in the settings page.")]
    InvalidMac,

    #[error("Could not enable monitor mode on '{0}'")]
    MonitorFailed(String),

    #[error("Could not disable monitor mode on '{0}'")]
    ManagedFailed(String),
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_iface {
    use super::*;

    pub fn is_monitor_mode(iface: &str) -> Result<bool, IfaceError> {
        let out = Command::new("iw").args(["dev", iface, "info"]).output()?;
        if !out.status.success() {
            return Err(IfaceError::IfaceNotFound(iface.to_string()));
        }
        Ok(String::from_utf8(out.stdout)?.contains("type monitor"))
    }

    pub fn set_mac_address(iface: &str, mac: &MacMode) -> Result<(), IfaceError> {
        if !is_monitor_mode(iface)? {
            return Err(IfaceError::IfaceNotMonitor);
        }
        Command::new("ip")
            .args(["link", "set", "dev", iface, "down"])
            .output()?;

        let success = match mac {
            MacMode::Random => {
                Command::new("macchanger").args(["-A", iface]).output()?;
                true
            }
            MacMode::Default => {
                Command::new("macchanger").args(["-p", iface]).output()?;
                true
            }
            MacMode::Specific(m) => Command::new("macchanger")
                .args(["-m", m, iface])
                .output()?
                .status
                .success(),
        };

        Command::new("ip")
            .args(["link", "set", "dev", iface, "up"])
            .output()?;

        if !success {
            return Err(IfaceError::InvalidMac);
        }
        log::info!("{iface}: MAC address changed");
        Ok(())
    }

    fn set_interface_type(iface: &str, mode: &str) -> Result<bool, IfaceError> {
        Command::new("ip")
            .args(["link", "set", "dev", iface, "down"])
            .output()?;
        let r = Command::new("iw")
            .args(["dev", iface, "set", "type", mode])
            .output()?;
        Command::new("ip")
            .args(["link", "set", "dev", iface, "up"])
            .output()?;
        Ok(r.status.success())
    }

    pub fn enable_monitor_mode(iface: &str, kill_nm: bool) -> Result<(), IfaceError> {
        kill_network_manager_services(kill_nm);

        if is_monitor_mode(iface)? {
            *IFACE_WAS_MONITOR.lock().unwrap() = true;
            return Ok(());
        }
        if !set_interface_type(iface, "monitor")? {
            return Err(IfaceError::MonitorFailed(iface.to_string()));
        }
        log::info!("{iface}: monitor mode enabled");
        Ok(())
    }

    pub fn disable_monitor_mode(iface: &str) -> Result<(), IfaceError> {
        if !is_monitor_mode(iface)? {
            return Ok(());
        }
        let mut was = IFACE_WAS_MONITOR.lock().unwrap();
        if *was {
            *was = false;
            return Ok(());
        }
        drop(was);
        if !set_interface_type(iface, "managed")? {
            return Err(IfaceError::ManagedFailed(iface.to_string()));
        }
        log::info!("{iface}: monitor mode disabled");
        Ok(())
    }
}

// ── macOS implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_iface {
    use super::*;

    /// Check if `iface` is currently in monitor mode via `ifconfig`.
    pub fn is_monitor_mode(iface: &str) -> Result<bool, IfaceError> {
        let out = Command::new("ifconfig").arg(iface).output()?;
        if !out.status.success() {
            return Err(IfaceError::IfaceNotFound(iface.to_string()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).contains("monitor"))
    }

    /// Change the MAC address using `ifconfig ether` (macOS equivalent of macchanger).
    pub fn set_mac_address(iface: &str, mac: &MacMode) -> Result<(), IfaceError> {
        let mac_str = match mac {
            MacMode::Random => random_mac(),
            MacMode::Default => return restore_hardware_mac(iface),
            MacMode::Specific(m) => m.clone(),
        };

        Command::new("ifconfig")
            .args([iface, "down"])
            .output()?;

        let success = Command::new("ifconfig")
            .args([iface, "ether", &mac_str])
            .output()?
            .status
            .success();

        Command::new("ifconfig")
            .args([iface, "up"])
            .output()?;

        if !success {
            return Err(IfaceError::InvalidMac);
        }
        log::info!("{iface}: MAC address changed to {mac_str}");
        Ok(())
    }

    fn random_mac() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0xdeadbeef_u64);
        // Simple LCG MAC with locally-administered bit set.
        let h = seed.wrapping_mul(6364136223846793005_u64).wrapping_add(1);
        let b = [
            (0x02 | (seed & 0xfe)) as u8,
            ((seed >> 8) & 0xff) as u8,
            ((seed >> 16) & 0xff) as u8,
            ((seed >> 24) & 0xff) as u8,
            (h & 0xff) as u8,
            ((h >> 8) & 0xff) as u8,
        ];
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }

    fn restore_hardware_mac(iface: &str) -> Result<(), IfaceError> {
        // networksetup can restore the hardware MAC on macOS.
        Command::new("networksetup")
            .args(["-setairportpower", iface, "off"])
            .output()?;
        Command::new("networksetup")
            .args(["-setairportpower", iface, "on"])
            .output()?;
        log::info!("{iface}: MAC address restored to hardware default");
        Ok(())
    }

    /// Enable monitor mode on macOS using the `airport` utility.
    pub fn enable_monitor_mode(iface: &str, _kill_nm: bool) -> Result<(), IfaceError> {
        // Disassociate from any current network first.
        let _ = Command::new(super::AIRPORT_PATH)
            .args(["-z"])
            .output();

        // airport does not expose a persistent monitor-mode toggle the way `iw` does;
        // libpcap's rfmon flag handles the actual mode switch when the capture opens.
        // We just mark the interface as committed here.
        *IFACE_WAS_MONITOR.lock().unwrap() = false;
        log::info!("{iface}: prepared for monitor mode (rfmon via libpcap)");
        Ok(())
    }

    /// Restore managed mode on macOS by reassociating via networksetup.
    pub fn disable_monitor_mode(iface: &str) -> Result<(), IfaceError> {
        Command::new("networksetup")
            .args(["-setairportpower", iface, "off"])
            .output()?;
        Command::new("networksetup")
            .args(["-setairportpower", iface, "on"])
            .output()?;
        log::info!("{iface}: monitor mode disabled");
        Ok(())
    }
}

// ── Public API (same signatures on both platforms) ────────────────────────────

/// Check if an interface is in monitor mode.
pub fn is_monitor_mode(iface: &str) -> Result<bool, IfaceError> {
    #[cfg(target_os = "linux")]
    return linux_iface::is_monitor_mode(iface);
    #[cfg(target_os = "macos")]
    return macos_iface::is_monitor_mode(iface);
}

/// Set the MAC address of an interface according to the requested mode.
pub fn set_mac_address(iface: &str, mac: &MacMode) -> Result<(), IfaceError> {
    #[cfg(target_os = "linux")]
    return linux_iface::set_mac_address(iface, mac);
    #[cfg(target_os = "macos")]
    return macos_iface::set_mac_address(iface, mac);
}

/// Enable monitor mode on an interface.
pub fn enable_monitor_mode(iface: &str, kill_network_manager: bool) -> Result<(), IfaceError> {
    #[cfg(target_os = "linux")]
    return linux_iface::enable_monitor_mode(iface, kill_network_manager);
    #[cfg(target_os = "macos")]
    return macos_iface::enable_monitor_mode(iface, kill_network_manager);
}

/// Disable monitor mode on an interface, switching it back to managed mode.
pub fn disable_monitor_mode(iface: &str) -> Result<(), IfaceError> {
    #[cfg(target_os = "linux")]
    return linux_iface::disable_monitor_mode(iface);
    #[cfg(target_os = "macos")]
    return macos_iface::disable_monitor_mode(iface);
}

/// Get the current interface
pub fn get_iface() -> Option<String> {
    IFACE.lock().unwrap().clone()
}

/// Set the current interface
pub fn set_iface(iface: String) {
    IFACE.lock().unwrap().replace(iface);
}

/// Clear the current interface
pub fn clear_iface() {
    IFACE.lock().unwrap().take();
}

/// List of Linux services that can interfere with wireless card management.
#[cfg(target_os = "linux")]
const INTERFERENCE_SERVICES: [&str; 19] = [
    "wpa_action",
    "wpa_supplicant",
    "wpa_cli",
    "dhclient",
    "ifplugd",
    "dhcdbd",
    "dhcpcd",
    "udhcpc",
    "NetworkManager",
    "knetworkmanager",
    "avahi-autoipd",
    "avahi-daemon",
    "wlassistant",
    "wifibox",
    "net_applet",
    "wicd-daemon",
    "wicd-client",
    "iwd",
    "hostapd",
];

/// Kill interfering network-manager services (Linux/systemctl only).
#[cfg(target_os = "linux")]
fn kill_network_manager_services(enabled: bool) {
    if !enabled {
        return;
    }
    if !deps::is_installed(deps::SYSTEMCTL) {
        log::warn!("systemctl not found, skipping network manager kill");
        return;
    }
    for service in INTERFERENCE_SERVICES {
        let running = match Command::new("systemctl")
            .args(["is-active", service])
            .output()
        {
            Ok(out) => out.status.success(),
            Err(_) => continue,
        };
        if running {
            Command::new("systemctl")
                .args(["stop", service])
                .output()
                .ok();
            SERVICES_TO_RESTORE
                .lock()
                .unwrap()
                .push(service.to_string());
            log::warn!("killed '{service}'");
        }
    }
}

/// Restore any network-manager services killed earlier (Linux/systemctl only).
#[cfg(target_os = "linux")]
pub fn restore_network_manager() -> Result<(), IfaceError> {
    if !deps::is_installed(deps::SYSTEMCTL) {
        return Ok(());
    }
    let services: Vec<_> = SERVICES_TO_RESTORE.lock().unwrap().drain(..).collect();
    for service in services {
        Command::new("systemctl")
            .args(["start", &service])
            .output()?;
        log::warn!("restored '{service}'");
    }
    Ok(())
}

/// macOS: no systemctl; network managers are not killed — libpcap handles RFMON.
#[cfg(target_os = "macos")]
pub fn restore_network_manager() -> Result<(), IfaceError> {
    Ok(())
}
