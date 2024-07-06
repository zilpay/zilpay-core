use prost_build::Config;
use std::io::Result;

fn main() -> Result<()> {
    Config::new()
        .out_dir("src/")
        .compile_protos(&["protos/ZilliqaMessage.proto"], &["protos/"])?;

    Ok(())
}
