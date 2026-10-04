//! Unprivileged interface queries, run directly by the GUI.
//!
//! Listing interfaces (sysfs) and probing 5 GHz capability (sysfs + `iw phy`)
//! need no privilege, so they stay in the GUI. Keeping them here — rather than
//! behind the agent — is what lets the interface picker open and populate
//! without ever escalating; the agent is only started once the user commits to
//! a privileged action (putting a card into monitor mode).

use super::AgentError;
use std::process::Command;

/// Get the available wireless interfaces.
pub fn get_interfaces() -> Result<Vec<String>, AgentError> {
    #[cfg(target_os = "linux")]
    {
        const NET_PATH: &str = "/sys/class/net";
        let entries = std::fs::read_dir(NET_PATH)
            .map_err(|e| AgentError(format!("could not read '{NET_PATH}': {e}")))?;
        let mut ifaces: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().join("phy80211").exists())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        ifaces.sort();
        return Ok(ifaces);
    }

    #[cfg(target_os = "macos")]
    {
        // `networksetup -listallhardwareports` lists every NIC with its device name.
        // We keep only AirPort / Wi-Fi entries.
        let out = Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
            .map_err(|e| AgentError(format!("networksetup failed: {e}")))?;

        let text = String::from_utf8_lossy(&out.stdout);
        let mut ifaces: Vec<String> = Vec::new();
        let mut is_wifi_block = false;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("Hardware Port:") {
                let port = line.trim_start_matches("Hardware Port:").trim().to_lowercase();
                is_wifi_block = port.contains("wi-fi")
                    || port.contains("airport")
                    || port.contains("wireless");
            } else if is_wifi_block && line.starts_with("Device:") {
                let dev = line.trim_start_matches("Device:").trim().to_string();
                if !dev.is_empty() {
                    ifaces.push(dev);
                }
            }
        }

        ifaces.sort();
        return Ok(ifaces);
    }
}

/// Check if an interface supports 5 GHz.
pub fn is_5ghz_supported(iface: &str) -> Result<bool, AgentError> {
    #[cfg(target_os = "linux")]
    {
        let phy_path = format!("/sys/class/net/{iface}/phy80211");
        let phy_link = std::fs::read_link(&phy_path)
            .map_err(|e| AgentError(format!("could not read '{phy_path}': {e}")))?;
        let phy_name = phy_link
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AgentError("could not parse PHY name".to_string()))?;
        let out = Command::new("iw")
            .args(["phy", phy_name, "info"])
            .output()
            .map_err(|e| AgentError(format!("failed to query PHY '{phy_name}': {e}")))?;
        if !out.status.success() {
            return Err(AgentError(format!("PHY '{phy_name}' could not be found")));
        }
        let output = String::from_utf8_lossy(&out.stdout);
        return Ok(output.contains("5200 MHz") || output.contains("5200.0 MHz"));
    }

    #[cfg(target_os = "macos")]
    {
        // Use the airport utility to check supported channels; 5 GHz channels are > 14.
        const AIRPORT: &str = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
        let out = Command::new(AIRPORT)
            .args(["-I"])
            .output()
            .map_err(|e| AgentError(format!("airport -I failed: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // If the current channel is > 14, we know 5 GHz is available.
        for line in text.lines() {
            if line.trim().starts_with("channel:") {
                let ch_str = line.split(':').nth(1).unwrap_or("").trim().to_string();
                // channel may be "36,+1" on 5 GHz; take the numeric prefix.
                let ch: u32 = ch_str
                    .split(',')
                    .next()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                if ch > 14 {
                    return Ok(true);
                }
            }
        }
        // Fall back: assume 5 GHz is supported on modern Macs.
        return Ok(true);
    }
}
