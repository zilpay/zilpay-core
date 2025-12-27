use errors::keypair::PubKeyError;

type Result<T> = std::result::Result<T, PubKeyError>;

pub trait ByteCodec: Sized {
    fn to_byte(&self) -> u8;
    fn from_byte(byte: u8) -> Result<Self>;
}

impl ByteCodec for bitcoin::Network {
    fn to_byte(&self) -> u8 {
        match self {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Testnet4 => 2,
            bitcoin::Network::Signet => 3,
            bitcoin::Network::Regtest => 4,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(bitcoin::Network::Bitcoin),
            1 => Ok(bitcoin::Network::Testnet),
            2 => Ok(bitcoin::Network::Testnet4),
            3 => Ok(bitcoin::Network::Signet),
            4 => Ok(bitcoin::Network::Regtest),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

impl ByteCodec for bitcoin::AddressType {
    fn to_byte(&self) -> u8 {
        match self {
            bitcoin::AddressType::P2pkh => 0,
            bitcoin::AddressType::P2sh => 1,
            bitcoin::AddressType::P2wpkh => 2,
            bitcoin::AddressType::P2wsh => 3,
            bitcoin::AddressType::P2tr => 4,
            bitcoin::AddressType::P2a => 5,
            &_ => todo!(),
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(bitcoin::AddressType::P2pkh),
            1 => Ok(bitcoin::AddressType::P2sh),
            2 => Ok(bitcoin::AddressType::P2wpkh),
            3 => Ok(bitcoin::AddressType::P2wsh),
            4 => Ok(bitcoin::AddressType::P2tr),
            5 => Ok(bitcoin::AddressType::P2a),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

pub fn create_btc_address(
    pk_bytes: &[u8],
    network: bitcoin::Network,
    addr_type: bitcoin::AddressType,
) -> Result<bitcoin::Address> {
    use bitcoin::{CompressedPublicKey, KnownHrp};

    let compressed_pk =
        CompressedPublicKey::from_slice(pk_bytes).map_err(|_| PubKeyError::FailIntoPubKey)?;

    let hrp: KnownHrp = network.into();

    let addr = match addr_type {
        bitcoin::AddressType::P2pkh => bitcoin::Address::p2pkh(&compressed_pk, network),
        bitcoin::AddressType::P2wpkh => bitcoin::Address::p2wpkh(&compressed_pk, hrp),
        bitcoin::AddressType::P2tr => {
            use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
            let x_only_pk = XOnlyPublicKey::from(compressed_pk.0);
            let secp = Secp256k1::new();
            bitcoin::Address::p2tr(&secp, x_only_pk, None, hrp)
        }
        _ => return Err(PubKeyError::InvalidKeyType),
    };

    Ok(addr)
}
