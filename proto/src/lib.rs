pub mod zilliqa_proto {
    include!("zilliqa_message.rs");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structure() {
        let test = zilliqa_proto::pm_hello::Data {
            pubkey: None,
            listenport: 0,
        };

        assert_eq!(test.pubkey, None);
        assert_eq!(test.listenport, 0);
    }
}
