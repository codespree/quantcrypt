#[cfg(test)]
macro_rules! test_cea {
    ($cea:expr) => {{
        let is_aad_supported = $cea.get_cea_info().is_aad_supported;
        use crate::cea::cea_manager::CeaManager;
        let key = $cea.key_gen().unwrap();
        let plaintext = b"Hello, world!";
        let (tag, ciphertext) = $cea.encrypt(&key, None, plaintext, None, None).unwrap();
        let decrypted = CeaManager::decrypt(&key, &tag, &ciphertext, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        if !is_aad_supported {
            return;
        }

        // Test with AAD
        let aad = b"Additional Authenticated Data";
        let (tag, ciphertext) = $cea
            .encrypt(&key, None, plaintext, Some(aad), None)
            .unwrap();
        let decrypted = CeaManager::decrypt(&key, &tag, &ciphertext, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // // Test decryption with wrong auth data
        let decrypted =
            CeaManager::decrypt(&key, &tag, &ciphertext, Some(b"Wrong AAD")).unwrap_err();
        assert_eq!(QuantCryptError::InvalidCiphertext, decrypted);

        // Test decryption with wrong tag
        let tag = vec![0u8; tag.len()];
        let decrypted = CeaManager::decrypt(&key, &tag, &ciphertext, Some(aad)).unwrap_err();
        assert_eq!(QuantCryptError::InvalidCiphertext, decrypted);

        // Test with custom nonce
        let nonce = b"Custom nonce";
        let (tag, ciphertext) = $cea
            .encrypt(&key, Some(nonce), plaintext, None, None)
            .unwrap();
        let decrypted = CeaManager::decrypt(&key, &tag, &ciphertext, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }};
}

#[cfg(test)]
pub(crate) use test_cea;
