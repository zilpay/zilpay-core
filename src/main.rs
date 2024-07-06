fn main() {
    let r = prost_build::compile_protos(&["src/zilliqa.proto"], &["src/"]);

    dbg!(&r);
}
