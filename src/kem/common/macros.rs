#[cfg(test)]
macro_rules! test_kem {
    ($kem:expr) => {{
        let mut kem = $kem.unwrap();
        let (pk, sk) = kem.key_gen().unwrap();

        let kem_info = kem.get_kem_info();

        let expected_pk_len = kem_info.pk_byte_len;
        if let Some(expected_pk_len) = expected_pk_len {
            assert_eq!(pk.len(), expected_pk_len);
        }

        let expected_sk_len = kem_info.sk_byte_len;
        if let Some(expected_sk_len) = expected_sk_len {
            assert_eq!(sk.len(), expected_sk_len);
        }

        let (ss, ct) = kem.encap(&pk).unwrap();
        let expected_ct_len = kem_info.ct_byte_len;
        if let Some(expected_ct_len) = expected_ct_len {
            assert_eq!(ct.len(), expected_ct_len);
        }

        let expected_ss_len = kem_info.ss_byte_len;
        assert_eq!(ss.len(), expected_ss_len);

        let ss2 = kem.decap(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);

        // Should generate different keys
        let (pk2, sk2) = kem.key_gen().unwrap();
        assert_ne!(pk, pk2);
        assert_ne!(sk, sk2);

        // Should generate the same keys
        let seed = [0u8; 32];
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_seed(seed);

        let (pk3, sk3) = kem.key_gen_with_rng(&mut rng).unwrap();

        // Seed it again
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (pk4, sk4) = kem.key_gen_with_rng(&mut rng).unwrap();

        assert_eq!(pk3, pk4);
        assert_eq!(sk3, sk4);

        // Length of shared secrets should be according to the curve
        assert_eq!(ss.len(), expected_ss_len);
    }};
}

#[cfg(test)]
pub(crate) use test_kem;
