fn main() {
    let proto_root = "tron-protocol";

    let protos = [
        "core/Tron.proto",
        "core/contract/common.proto",
        "core/contract/balance_contract.proto",
        "core/contract/smart_contract.proto",
        "core/contract/account_contract.proto",
        "core/contract/asset_issue_contract.proto",
        "core/contract/exchange_contract.proto",
        "core/contract/market_contract.proto",
        "core/contract/proposal_contract.proto",
        "core/contract/shield_contract.proto",
        "core/contract/storage_contract.proto",
        "core/contract/vote_asset_contract.proto",
        "core/contract/witness_contract.proto",
        "api/api.proto",
        "api/zksnark.proto",
    ];

    let proto_paths: Vec<String> = protos.iter().map(|p| format!("{}/{}", proto_root, p)).collect();
    let proto_refs: Vec<&str> = proto_paths.iter().map(|s| s.as_str()).collect();

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .out_dir("src/tron_generated")
        .compile_protos(&proto_refs, &[proto_root, "."])
        .expect("Failed to compile Tron protos");
}
