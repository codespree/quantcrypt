#[cfg(test)]
macro_rules! test_dsa {
    ($dsa:expr) => {{
        let mut dsa = $dsa.unwrap();
        let (pk, sk) = dsa.key_gen().unwrap();

        let pk2 = dsa.get_public_key(&sk).unwrap();
        assert_eq!(pk, pk2);

        let dsa_info = dsa.get_dsa_info();
        let expected_pk_len = dsa_info.pk_byte_len;
        if let Some(expected_pk_len) = expected_pk_len {
            assert_eq!(pk.len(), expected_pk_len);
        }
        let expected_sk_len = dsa_info.sk_byte_len;
        if let Some(expected_sk_len) = expected_sk_len {
            assert_eq!(sk.len(), expected_sk_len);
        }

        let msg = b"Hello, world! 
        This is a test message for the DSA algorithm.";
        let signature = dsa.sign(&sk, msg).unwrap();
        let expected_signature_len = dsa_info.sig_byte_len;
        if let Some(expected_signature_len) = expected_signature_len {
            assert_eq!(signature.len(), expected_signature_len);
        }

        let verified = dsa.verify(&pk, msg, &signature).unwrap();
        assert!(verified);
    }};
}

#[cfg(test)]
pub(crate) use test_dsa;
