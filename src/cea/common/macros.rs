#[cfg(test)]
macro_rules! test_cea {
    ($cea:expr) => {{
        use crate::cea::cea_manager::CaeManager;
        let key = $cea.key_gen().unwrap();
        let plaintext = b"Hello, world!";
        let ciphertext = $cea.encrypt(&key, plaintext, None, None).unwrap();
        let decrypted = CaeManager::decrypt(&key, &ciphertext, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test with AAD
        let aad = b"Additional Authenticated Data";
        let ciphertext = $cea.encrypt(&key, plaintext, Some(aad), None).unwrap();
        let decrypted = CaeManager::decrypt(&key, &ciphertext, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Test decryption with wrong auth data
        let decrypted = CaeManager::decrypt(&key, &ciphertext, Some(b"Wrong AAD")).unwrap_err();
        assert_eq!(QuantCryptError::InvalidCiphertext, decrypted);
    }};
}

#[cfg(test)]
pub(crate) use test_cea;
