use errors::storage::LocalStorageError;
use std::borrow::Cow;
use std::mem::size_of;

type Result<T> = std::result::Result<T, LocalStorageError>;

#[derive(Debug)]
pub struct DataWarp {
    pub payload: Vec<u8>,
    // Storage verions
    pub version: u16,
}

impl PartialEq for DataWarp {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl DataWarp {
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let mut bytes: Vec<u8> =
            Vec::with_capacity(size_of::<usize>() + payload_len + size_of::<u16>());

        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.version.to_le_bytes());

        bytes
    }

    pub fn from_bytes(bytes: Cow<[u8]>) -> Result<Self> {
        if bytes.len() < size_of::<usize>() + size_of::<u16>() {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());

        let payload_len = usize::from_le_bytes(
            len_bytes
                .as_ref()
                .try_into()
                .map_err(|_| LocalStorageError::PayloadLengthError)?,
        );
        let remains_len = payload_len
            .checked_add(size_of::<u16>())
            .ok_or(LocalStorageError::InvalidBytesSizeOverflow)?;

        if rest.len() < remains_len {
            return Err(LocalStorageError::InsufficientBytes);
        }

        let (payload, version_bytes) = rest.split_at(payload_len);
        let version = u16::from_le_bytes(
            version_bytes[..size_of::<u16>()]
                .try_into()
                .or(Err(LocalStorageError::PayloadVersionParseError))?,
        );

        Ok(Self {
            payload: payload.to_vec(),
            version,
        })
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_datawarp_serialization_deserialization() {
        let data = DataWarp {
            payload: b"Hello, World!".to_vec(),
            version: 1,
        };

        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), size_of::<usize>() + 13 + size_of::<u16>());

        let (len_bytes, rest) = bytes.split_at(size_of::<usize>());
        assert_eq!(usize::from_le_bytes(len_bytes.try_into().unwrap()), 13);

        let (payload_bytes, version_bytes) = rest.split_at(13);
        assert_eq!(payload_bytes, b"Hello, World!");
        assert_eq!(u16::from_le_bytes(version_bytes.try_into().unwrap()), 1);

        let res_data: DataWarp = DataWarp::from_bytes(bytes.into()).unwrap();

        assert_eq!(res_data, data);
    }

    #[test]
    fn test_datawarp_roundtrip() {
        let original = DataWarp {
            payload: b"Test data".to_vec(),
            version: 42,
        };

        let bytes = original.to_bytes();
        let deserialized = DataWarp::from_bytes(bytes.into()).unwrap();

        assert_eq!(original.payload, deserialized.payload);
        assert_eq!(original.version, deserialized.version);
    }

    #[test]
    fn test_datawarp_invalid_payload() {
        let invalid_bytes = vec![255; 10]; // Invalid UTF-8
        let result = DataWarp::from_bytes(invalid_bytes.into());

        assert!(matches!(
            result,
            Err(LocalStorageError::InvalidBytesSizeOverflow)
        ));
    }

    #[test]
    fn test_datawarp_invalid_version() {
        let mut bytes = b"Valid payload".to_vec();
        bytes.push(0); // Add only one byte for version instead of two
        let result = DataWarp::from_bytes(bytes.into());
        assert!(matches!(result, Err(LocalStorageError::InsufficientBytes)));
    }
}
