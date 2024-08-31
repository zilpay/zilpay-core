use std::{mem::size_of, ops::Add};

use bincode::{FromBytes, ToVecBytes};
use config::storage::STORAGE_VERSION;
use zil_errors::LocalStorageError;

#[derive(Debug)]
pub struct DataWarp<ST: ToVecBytes + FromBytes> {
    pub payload: ST,
    // Storage verions
    pub version: u16,
}

impl<ST> FromBytes for DataWarp<ST>
where
    ST: ToVecBytes + FromBytes,
{
    type Error = LocalStorageError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < size_of::<usize>() + size_of::<u16>() {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());

        let payload_len = usize::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| LocalStorageError::PayloadLengthError)?,
        );
        let remains_len = payload_len
            .checked_add(size_of::<u16>())
            .ok_or(LocalStorageError::InvalidBytesSizeOverflow)?;

        if rest.len() < remains_len {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (payload_bytes, version_bytes) = rest.split_at(payload_len);
        let payload =
            ST::from_bytes(payload_bytes).map_err(|_| LocalStorageError::PayloadParseError)?;
        let version = u16::from_le_bytes(
            version_bytes[..size_of::<u16>()]
                .try_into()
                .or(Err(LocalStorageError::PayloadVersionParseError))?,
        );

        Ok(Self { payload, version })
    }
}

impl<ST> ToVecBytes for DataWarp<ST>
where
    ST: ToVecBytes + FromBytes,
{
    fn to_bytes(&self) -> Vec<u8> {
        let payload_bytes = ST::to_bytes(&self.payload);
        let payload_len = payload_bytes.len();
        let mut bytes: Vec<u8> =
            Vec::with_capacity(size_of::<usize>() + payload_len + size_of::<u16>());

        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&payload_bytes);
        bytes.extend_from_slice(&self.version.to_le_bytes());

        bytes
    }
}

impl<ST> PartialEq for DataWarp<ST>
where
    ST: PartialEq + ToVecBytes + FromBytes,
{
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl<ST: Default> Default for DataWarp<ST>
where
    ST: ToVecBytes + FromBytes,
{
    fn default() -> Self {
        DataWarp {
            payload: ST::default(),
            version: STORAGE_VERSION,
        }
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct TestPayload {
        data: String,
    }

    impl ToVecBytes for TestPayload {
        fn to_bytes(&self) -> Vec<u8> {
            self.data.as_bytes().to_vec()
        }
    }

    impl FromBytes for TestPayload {
        type Error = LocalStorageError;

        fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
            String::from_utf8(bytes.to_vec())
                .map(|data| TestPayload { data })
                .map_err(|_| LocalStorageError::PayloadParseError)
        }
    }

    #[test]
    fn test_datawarp_serialization_deserialization() {
        let data = DataWarp {
            payload: TestPayload {
                data: "Hello, World!".to_string(),
            },
            version: 1,
        };

        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), size_of::<usize>() + 13 + size_of::<u16>());

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());
        assert_eq!(usize::from_le_bytes(len_bytes.try_into().unwrap()), 13);

        let (payload_bytes, version_bytes) = rest.split_at(13);
        assert_eq!(payload_bytes, b"Hello, World!");
        assert_eq!(u16::from_le_bytes(version_bytes.try_into().unwrap()), 1);

        let res_data: DataWarp<TestPayload> = DataWarp::from_bytes(&bytes).unwrap();

        assert_eq!(res_data, data);
    }

    #[test]
    fn test_datawarp_roundtrip() {
        let original = DataWarp {
            payload: TestPayload {
                data: "Test data".to_string(),
            },
            version: 42,
        };

        let bytes = original.to_bytes();
        let deserialized = DataWarp::<TestPayload>::from_bytes(&bytes).unwrap();

        assert_eq!(original.payload.data, deserialized.payload.data);
        assert_eq!(original.version, deserialized.version);
    }

    #[test]
    fn test_datawarp_invalid_payload() {
        let invalid_bytes = vec![255; 10]; // Invalid UTF-8
        let result = DataWarp::<TestPayload>::from_bytes(&invalid_bytes);

        assert!(matches!(
            result,
            Err(LocalStorageError::InvalidBytesSizeOverflow)
        ));
    }

    #[test]
    fn test_datawarp_invalid_version() {
        let mut bytes = b"Valid payload".to_vec();
        bytes.push(0); // Add only one byte for version instead of two
        let result = DataWarp::<TestPayload>::from_bytes(&bytes);
        assert!(matches!(result, Err(LocalStorageError::InsufficientBytes)));
    }
}
