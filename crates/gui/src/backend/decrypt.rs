use crate::types::*;
use airgorah_common::deps;
use std::process::{Command, Stdio};

const CRUNCH_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const CRUNCH_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CRUNCH_NUMBERS: &str = "0123456789";
const CRUNCH_SYMBOLS: &str = " @!#$%^&*()-_+=~`[]{}|:;<>,.?/\\";

#[derive(thiserror::Error, Debug)]
pub enum DecryptError {
    #[error("Input/Output error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    MissingTool(String),
}

/// Spawn an OS-appropriate terminal window running `cmd`.
fn spawn_terminal(title: &str, cmd: &str) -> Result<(), DecryptError> {
    #[cfg(target_os = "linux")]
    {
        Command::new("xterm")
            .stdin(Stdio::null())
            .args(["-hold", "-T", title, "-e", "sh", "-c", cmd])
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        // Use `open -a Terminal` with a helper script so the window stays open.
        let script = format!(
            "tell application \"Terminal\" to do script \"{}; echo; echo '--- Press Return to close ---'; read\"",
            cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        Command::new("osascript")
            .stdin(Stdio::null())
            .args(["-e", &script])
            .spawn()?;
    }
    Ok(())
}

/// Launch a terminal running aircrack-ng against a handshake with the given wordlist.
pub fn run_decrypt_wordlist_process(
    handshake: &str,
    bssid: &str,
    essid: &str,
    wordlist: &str,
) -> Result<(), DecryptError> {
    if !deps::is_installed(deps::AIRCRACK_NG) {
        return Err(DecryptError::MissingTool(
            "aircrack-ng is not installed".to_string(),
        ));
    }
    let title = format!("WPA Decryption ({essid})");
    let cmd = format!("aircrack-ng '{handshake}' -b '{bssid}' -w '{wordlist}'");
    spawn_terminal(&title, &cmd)
}

/// Launch a terminal running crunch piped to aircrack-ng for bruteforce decryption.
pub fn run_decrypt_bruteforce_process(
    handshake: &str,
    bssid: &str,
    essid: &str,
    charset: &BruteforceCharset,
    min: u64,
    max: u64,
) -> Result<(), DecryptError> {
    let charset_str = match charset {
        BruteforceCharset::Params(settings) => format!(
            "{}{}{}{}",
            if settings.lowercase { CRUNCH_LOWERCASE } else { "" },
            if settings.uppercase { CRUNCH_UPPERCASE } else { "" },
            if settings.numbers { CRUNCH_NUMBERS } else { "" },
            if settings.symbols { CRUNCH_SYMBOLS } else { "" },
        ),
        BruteforceCharset::Specific(custom) => custom.to_owned(),
    };

    if !deps::is_installed("crunch") {
        return Err(DecryptError::MissingTool(
            "crunch is not installed".to_string(),
        ));
    }
    if !deps::is_installed(deps::AIRCRACK_NG) {
        return Err(DecryptError::MissingTool(
            "aircrack-ng is not installed".to_string(),
        ));
    }

    let title = format!("WPA Decryption ({essid})");
    let cmd = format!(
        "crunch {min} {max} '{charset_str}' | aircrack-ng -w - -b '{bssid}' '{handshake}'"
    );
    spawn_terminal(&title, &cmd)
}

/// Launch hashcat for GPU-accelerated WPA/WPA2 cracking against a .hccapx / .22000 file.
pub fn run_decrypt_hashcat_process(
    hccapx: &str,
    essid: &str,
    wordlist: &str,
    rules: Option<&str>,
) -> Result<(), DecryptError> {
    if !deps::is_installed(deps::HASHCAT) {
        return Err(DecryptError::MissingTool(
            "hashcat is not installed".to_string(),
        ));
    }
    let title = format!("Hashcat GPU crack ({essid})");
    let rule_arg = rules.map(|r| format!(" -r '{r}'")).unwrap_or_default();
    // Mode 22000 is WPA-PBKDF2-PMKID+EAPOL (hashcat ≥ 6.0), mode 2500 for .hccapx.
    let mode = if hccapx.ends_with(".22000") { "22000" } else { "2500" };
    let cmd = format!("hashcat -m {mode} '{hccapx}' '{wordlist}'{rule_arg}");
    spawn_terminal(&title, &cmd)
}
