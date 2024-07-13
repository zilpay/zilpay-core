use prost_build::Config;
use std::io::Result;

fn main() -> Result<()> {
    Config::new()
        .out_dir("src/")
        .compile_protos(&["src/ZilliqaMessage.proto"], &["protos/"])?;

    Ok(())
}
