use super::{get_aps, get_unlinked_clients};
use airgorah_common::types::{AP, Client};

use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize)]
struct Report {
    pub access_points: Vec<AP>,
    pub unlinked_clients: Vec<Client>,
}

#[derive(thiserror::Error, Debug)]
pub enum CapError {
    #[error("Input/Output error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Json error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Save a JSON report of the current scan snapshot.
pub fn save_report(path: &str) -> Result<(), CapError> {
    let access_points = get_aps().values().cloned().collect::<Vec<AP>>();
    let unlinked_clients = get_unlinked_clients()
        .values()
        .cloned()
        .collect::<Vec<Client>>();

    let report = Report {
        access_points,
        unlinked_clients,
    };

    let json_data = serde_json::to_string_pretty::<Report>(&report)?;
    let mut file = File::create(path)?;
    file.write_all(json_data.as_bytes())?;
    log::info!("report saved to '{path}'");
    Ok(())
}

/// Save a CSV report of discovered APs (airodump-ng compatible format).
pub fn save_csv_report(path: &str) -> Result<(), CapError> {
    let aps = get_aps();
    let clients = get_unlinked_clients();

    let mut out = File::create(path)?;

    // AP header
    writeln!(
        out,
        "BSSID,First time seen,Last time seen,channel,Speed,Privacy,Cipher,Authentication,Power,# beacons,# IV,LAN IP,ID-length,ESSID,Key"
    )?;

    let mut sorted_aps: Vec<_> = aps.values().collect();
    sorted_aps.sort_by(|a, b| a.bssid.cmp(&b.bssid));

    for ap in &sorted_aps {
        let client_count = ap.clients.len();
        writeln!(
            out,
            "{},{},{},{},0,{},,,{},{},0,,,{},",
            ap.bssid,
            ap.first_time_seen,
            ap.last_time_seen,
            ap.channel,
            ap.privacy,
            ap.power,
            client_count,
            ap.essid,
        )?;
    }

    // Blank line + station header
    writeln!(out)?;
    writeln!(
        out,
        "Station MAC,First time seen,Last time seen,Power,# packets,BSSID,Probed ESSIDs"
    )?;

    // Linked clients
    for ap in &sorted_aps {
        let mut sorted_clients: Vec<_> = ap.clients.values().collect();
        sorted_clients.sort_by(|a, b| a.mac.cmp(&b.mac));
        for client in sorted_clients {
            writeln!(
                out,
                "{},{},{},{},{},{},{}",
                client.mac,
                client.first_time_seen,
                client.last_time_seen,
                client.power,
                client.packets,
                ap.bssid,
                client.probes,
            )?;
        }
    }

    // Unlinked clients
    let mut unlinked: Vec<_> = clients.values().collect();
    unlinked.sort_by(|a, b| a.mac.cmp(&b.mac));
    for client in unlinked {
        writeln!(
            out,
            "{},{},{},{},{},not associated,{}",
            client.mac,
            client.first_time_seen,
            client.last_time_seen,
            client.power,
            client.packets,
            client.probes,
        )?;
    }

    log::info!("CSV report saved to '{path}'");
    Ok(())
}
