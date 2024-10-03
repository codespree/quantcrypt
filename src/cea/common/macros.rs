#[cfg(test)]
macro_rules! test_cea {
    ($cea:expr) => {{
        use crate::cea::cea_manager::CaeManager;
        let key = $cea.key_gen().unwrap();
        let plaintext = b"Hello, world!";
        let (tag, ciphertext) = $cea.encrypt(&key, plaintext, None, None).unwrap();
        let decrypted = CaeManager::decrypt(&key, &tag, &ciphertext, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test with AAD
        let aad = b"Additional Authenticated Data";
        let (tag, ciphertext) = $cea.encrypt(&key, plaintext, Some(aad), None).unwrap();
        let decrypted = CaeManager::decrypt(&key, &tag, &ciphertext, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test decryption with wrong auth data
        let decrypted =
            CaeManager::decrypt(&key, &tag, &ciphertext, Some(b"Wrong AAD")).unwrap_err();
        assert_eq!(QuantCryptError::InvalidCiphertext, decrypted);

        // Test decryption with wrong tag
        let tag = vec![0u8; tag.len()];
        let decrypted = CaeManager::decrypt(&key, &tag, &ciphertext, Some(aad)).unwrap_err();
        assert_eq!(QuantCryptError::InvalidCiphertext, decrypted);
    }};
}

#[cfg(test)]
pub(crate) use test_cea;
