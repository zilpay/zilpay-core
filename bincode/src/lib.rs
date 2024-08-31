pub trait ToBytes<const N: usize> {
    type Error;
    fn to_bytes(&self) -> Result<[u8; N], Self::Error>;
}

pub trait ToVecBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes: Sized {
    type Error;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
}
