use std::{fs, io};

pub fn get_device_identifier() -> Result<Vec<String>, io::Error> {
    let paths = [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/board_serial",
    ];

    let identifier: Vec<String> = paths
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|s| s.trim().to_string())
        .collect();

    if identifier.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No device identifiers found",
        ));
    }

    Ok(identifier)
}
