use der::asn1::{BitString, OctetString};
use der_derive::Sequence;
use pkcs8::PrivateKeyInfo;

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
/// The public key for the composite KEM
pub struct CompositeKEMPublicKey {
    /// The public key for the post-quantum KEM
    pq_pk: BitString,
    /// The public key for the traditional KEM
    trad_pk: BitString,
}

impl CompositeKEMPublicKey {
    /// Create a new composite KEM public key
    ///
    /// # Arguments
    ///
    /// * `pq_pk` - The public key for the post-quantum KEM
    /// * `trad_pk` - The public key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite KEM public key
    pub fn new(pq_pk: &[u8], trad_pk: &[u8]) -> Self {
        let trad_pk = BitString::from_bytes(trad_pk).unwrap();
        let pq_pk = BitString::from_bytes(pq_pk).unwrap();
        Self { pq_pk, trad_pk }
    }

    /// Get the public key for the traditional KEM
    ///
    /// # Returns
    ///
    /// The public key for the traditional KEM
    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.as_bytes().unwrap().to_vec()
    }

    /// Get the public key for the post-quantum KEM
    ///
    /// # Returns
    ///
    /// The public key for the post-quantum KEM
    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.as_bytes().unwrap().to_vec()
    }
}

#[derive(Debug, Clone, Sequence)]
/// The private key for the composite KEM
pub struct CompositeKEMPrivateKey<'a> {
    /// The private key for the post-quantum KEM. The structure is OneAsymmetricKey
    pq_sk: PrivateKeyInfo<'a>,

    /// The private key for the traditional KEM. The structure is OneAsymmetricKey
    trad_sk: PrivateKeyInfo<'a>,
}

impl<'a> CompositeKEMPrivateKey<'a> {
    /// Create a new composite KEM private key
    ///
    /// # Arguments
    ///
    /// * `pq_sk` - The private key for the post-quantum KEM
    /// * `trad_sk` - The private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite KEM private key
    pub fn new(pq_sk: PrivateKeyInfo<'a>, trad_sk: PrivateKeyInfo<'a>) -> Self {
        Self { pq_sk, trad_sk }
    }

    /// Get the private key for the post-quantum KEM
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum KEM
    pub fn get_pq_sk(&self) -> &PrivateKeyInfo<'a> {
        &self.pq_sk
    }

    /// Get the private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// The private key for the traditional KEM
    pub fn get_trad_sk(&self) -> &PrivateKeyInfo<'a> {
        &self.trad_sk
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
/// The composite ciphertext value
pub struct CompositeCiphertextValue {
    /// The ciphertext for the post-quantum KEM
    pq_ct: OctetString,
    /// The ciphertext for the traditional KEM
    trad_ct: OctetString,
}

impl CompositeCiphertextValue {
    /// Create a new composite ciphertext value
    ///
    /// # Arguments
    ///
    /// * `pq_ct` - The ciphertext for the post-quantum KEM
    /// * `trad_ct` - The ciphertext for the traditional KEM
    pub fn new(pq_ct: &[u8], trad_ct: &[u8]) -> Self {
        let pq_ct = OctetString::new(pq_ct).unwrap();
        let trad_ct = OctetString::new(trad_ct).unwrap();
        Self { pq_ct, trad_ct }
    }

    /// Get the ciphertext for the post-quantum KEM
    ///
    /// # Returns
    ///
    /// The ciphertext for the post-quantum KEM
    pub fn get_pq_ct(&self) -> Vec<u8> {
        self.pq_ct.as_bytes().to_vec()
    }

    /// Get the ciphertext for the traditional KEM
    ///
    /// # Returns
    ///
    /// The ciphertext for the traditional KEM
    pub fn get_trad_ct(&self) -> Vec<u8> {
        self.trad_ct.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};
    use pkcs8::AlgorithmIdentifierRef;

    #[test]
    fn test_composite_kem_public_key() {
        let trad_bytes: Vec<u8> = vec![0, 1, 2];
        let pq_bytes: Vec<u8> = vec![4, 5, 6];

        let composite_kem_public_key = CompositeKEMPublicKey::new(&pq_bytes, &trad_bytes);

        // Encode the composite KEM public key
        let encoded = composite_kem_public_key.to_der().unwrap();

        // Write the encoded bytes to a file
        //std::fs::write("composite_kem_public_key.der", &encoded).unwrap();

        // Check that the encoded bytes are correct
        let decoded = CompositeKEMPublicKey::from_der(&encoded).unwrap();
        assert_eq!(decoded.get_trad_pk(), trad_bytes);
        assert_eq!(decoded.get_pq_pk(), pq_bytes);
    }

    #[test]
    fn test_composite_kem_secret_keys() {
        let trad_bytes: Vec<u8> = vec![0, 1, 2];
        let pq_bytes: Vec<u8> = vec![4, 5, 6];

        let trad_sk = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: "1.2.840.10045.2.1".parse().unwrap(),
                parameters: None,
            },
            private_key: &trad_bytes,
            public_key: None,
        };

        let pq_sk = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: "1.2.840.113549.1.1.1".parse().unwrap(),
                parameters: None,
            },
            private_key: &pq_bytes,
            public_key: None,
        };

        let composite_kem_private_key = CompositeKEMPrivateKey::new(pq_sk, trad_sk);

        // Encode the composite KEM private key
        let encoded = composite_kem_private_key.to_der().unwrap();

        // Write the encoded bytes to a file
        //std::fs::write("composite_kem_private_key.der", &encoded).unwrap();

        // Check that the encoded bytes are correct
        let decoded = CompositeKEMPrivateKey::from_der(&encoded).unwrap();

        assert_eq!(decoded.get_pq_sk().private_key, pq_bytes);
        assert_eq!(decoded.get_trad_sk().private_key, trad_bytes);

        assert_eq!(
            decoded.get_pq_sk().algorithm.oid,
            "1.2.840.113549.1.1.1".parse().unwrap()
        );
        assert_eq!(
            decoded.get_trad_sk().algorithm.oid,
            "1.2.840.10045.2.1".parse().unwrap()
        );
    }

    #[test]
    fn test_composite_ciphertext_value() {
        let trad_bytes: Vec<u8> = vec![0, 1, 2];
        let pq_bytes: Vec<u8> = vec![4, 5, 6];

        let composite_ciphertext_value = CompositeCiphertextValue::new(&pq_bytes, &trad_bytes);

        // Encode the composite KEM public key
        let encoded = composite_ciphertext_value.to_der().unwrap();

        // Write the encoded bytes to a file
        //std::fs::write("composite_ciphertext_value.der", &encoded).unwrap();

        // Check that the encoded bytes are correct
        let decoded = CompositeCiphertextValue::from_der(&encoded).unwrap();
        assert_eq!(decoded.get_trad_ct(), trad_bytes);
        assert_eq!(decoded.get_pq_ct(), pq_bytes);
    }
}
