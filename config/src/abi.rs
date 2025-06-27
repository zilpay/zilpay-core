pub const ERC20_ABI: &str = r#"[
    {
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "symbol",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {
                "name": "_owner",
                "type": "address"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "balance",
                "type": "uint256"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "",
                "type": "uint8"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_from",
                "type": "address"
            },
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transferFrom",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
   {
        "constant": false,
        "inputs": [
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    }
]"#;

pub const NON_LIQUID_DELEGATOR_ABI: &str = r#"[
    {
        "name": "getDelegatedAmount",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{ "type": "uint256" }]
    },
    {
        "name": "rewards",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{ "internalType": "uint256", "name": "", "type": "uint256" }]
    },
    {
        "name": "getDelegatedTotal",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{ "type": "uint256" }]
    }
]"#;

pub const DEPOSIT_ABI: &str = r#"[
    {
        "inputs": [],
        "name": "getFutureTotalStake",
        "outputs": [{ "internalType": "uint256", "name": "", "type": "uint256" }],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

pub const EVM_DELEGATOR_ABI: &str = r#"[
    {
        "name": "getStake",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{ "type": "uint256" }]
    },
    {
        "name": "getCommission",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{ "type": "uint256" }, { "type": "uint256" }]
    }
]"#;
