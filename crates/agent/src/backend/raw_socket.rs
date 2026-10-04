//! Shared raw socket helpers for capturing and injecting 802.11 frames.
//!
//! On Linux we use a raw `AF_PACKET` socket directly; on macOS we use libpcap
//! (`pcap` crate) in RFMON mode, which gives us the same radiotap-prefixed frames.

use std::io;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ── Linux implementation (AF_PACKET raw socket) ─────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::io;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// Open a raw `AF_PACKET` socket bound to `iface`.
    pub fn open(iface: &str) -> io::Result<OwnedFd> {
        let eth_p_all = (libc::ETH_P_ALL as u16).to_be();

        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        let ifindex = interface_index(iface)?;

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = eth_p_all;
        addr.sll_ifindex = ifindex as i32;

        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(socket)
    }

    pub fn set_recv_timeout(socket: &OwnedFd, millis: i64) -> io::Result<()> {
        let timeout = libc::timeval {
            tv_sec: millis / 1000,
            tv_usec: (millis % 1000) * 1000,
        };
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn recv(socket: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    pub fn send(socket: &OwnedFd, frame: &[u8]) -> io::Result<()> {
        let n = unsafe {
            libc::send(
                socket.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn interface_index(iface: &str) -> io::Result<u32> {
        let name = CString::new(iface).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains a nul")
        })?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(index)
    }
}

// ── macOS implementation (libpcap in RFMON mode) ─────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::io;
    use pcap::{Capture, Active, Device};
    use std::sync::{Arc, Mutex};

    /// A thin wrapper that lets the rest of the codebase treat a pcap capture
    /// handle the same way it treats an `OwnedFd` on Linux.
    pub struct PcapHandle {
        cap: Arc<Mutex<Capture<Active>>>,
        /// Scratch buffer for frames to be injected (pcap sendpacket path).
        iface: String,
    }

    impl PcapHandle {
        pub fn iface(&self) -> &str {
            &self.iface
        }

        pub fn cap(&self) -> &Arc<Mutex<Capture<Active>>> {
            &self.cap
        }
    }

    /// Open a libpcap capture on `iface` in RFMON (monitor) mode.
    pub fn open(iface: &str) -> io::Result<PcapHandle> {
        let cap = Capture::from_device(iface)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .rfmon(true)
            .immediate_mode(true)
            .snaplen(65535)
            .open()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(PcapHandle {
            cap: Arc::new(Mutex::new(cap)),
            iface: iface.to_string(),
        })
    }

    pub fn set_recv_timeout(handle: &PcapHandle, millis: i64) -> io::Result<()> {
        // pcap timeout is set at open time; on macOS immediate_mode covers this.
        // We store the intent but there is no post-open timeout API.
        let _ = (handle, millis);
        Ok(())
    }

    /// Read the next frame. Returns 0 on timeout/empty.
    pub fn recv(handle: &PcapHandle, buf: &mut [u8]) -> io::Result<usize> {
        let mut cap = handle.cap.lock().unwrap();
        match cap.next_packet() {
            Ok(pkt) => {
                let len = pkt.data.len().min(buf.len());
                buf[..len].copy_from_slice(&pkt.data[..len]);
                Ok(len)
            }
            Err(pcap::Error::TimeoutExpired) => Ok(0),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    /// Inject a raw frame via pcap `sendpacket`.
    pub fn send(handle: &PcapHandle, frame: &[u8]) -> io::Result<()> {
        let mut cap = handle.cap.lock().unwrap();
        cap.sendpacket(frame)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

// ── Public API — same signatures on both platforms ───────────────────────────

#[cfg(target_os = "linux")]
pub type Socket = std::os::fd::OwnedFd;

#[cfg(target_os = "macos")]
pub type Socket = macos::PcapHandle;

/// Open a capture/injection socket on the monitor interface.
pub fn open(iface: &str) -> io::Result<Socket> {
    #[cfg(target_os = "linux")]
    return linux::open(iface);
    #[cfg(target_os = "macos")]
    return macos::open(iface);
}

/// Set a receive timeout (milliseconds) so capture loops can hop and observe stop flags.
pub fn set_recv_timeout(socket: &Socket, millis: i64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::set_recv_timeout(socket, millis);
    #[cfg(target_os = "macos")]
    return macos::set_recv_timeout(socket, millis);
}

/// Receive one frame, returning the number of bytes read (0 on empty / timeout).
pub fn recv(socket: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    return linux::recv(socket, buf);
    #[cfg(target_os = "macos")]
    return macos::recv(socket, buf);
}

/// Inject one raw frame (radiotap + 802.11).
pub fn send(socket: &Socket, frame: &[u8]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::send(socket, frame);
    #[cfg(target_os = "macos")]
    return macos::send(socket, frame);
}
