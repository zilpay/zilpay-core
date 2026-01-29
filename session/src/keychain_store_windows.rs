use std::{io, process::Command};

fn query_machine_guid() -> Result<String, io::Error> {
    let output = Command::new("reg")
        .args(&[
            "query",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Registry query failed",
        ));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    output_str
        .lines()
        .find(|line| line.contains("MachineGuid"))
        .and_then(|line| line.split_whitespace().last())
        .map(String::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "MachineGuid not found"))
}

fn query_motherboard_serial() -> Result<String, io::Error> {
    let output = Command::new("wmic")
        .args(&["baseboard", "get", "serialnumber"])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "WMIC query failed"));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    output_str
        .lines()
        .nth(1)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "SerialNumber")
        .map(String::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Serial number not found"))
}

pub fn get_device_identifier() -> Result<Vec<String>, io::Error> {
    let mut identifier = Vec::new();
    identifier.push(query_machine_guid()?);

    if let Ok(serial) = query_motherboard_serial() {
        identifier.push(serial);
    }

    if identifier.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No device identifiers found",
        ));
    }

    Ok(identifier)
}
