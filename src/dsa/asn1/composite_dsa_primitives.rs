use der::asn1::{BitString, OctetString};
use der_derive::Sequence;
use pkcs8::PrivateKeyInfo;

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
/// The public key for the composite KEM
pub struct CompositeDsaPublicKey {
    /// The public key for the post-quantum KEM
    pq_pk: BitString,
    /// The public key for the traditional KEM
    trad_pk: BitString,
}

impl CompositeDsaPublicKey {
    /// Create a new composite DSA public key
    ///
    /// # Arguments
    ///
    /// * `pq_pk` - The public key for the post-quantum KEM
    /// * `trad_pk` - The public key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite DSA public key
    pub fn new(pq_pk: &[u8], trad_pk: &[u8]) -> Self {
        let trad_pk = BitString::from_bytes(trad_pk).unwrap();
        let pq_pk = BitString::from_bytes(pq_pk).unwrap();
        Self { pq_pk, trad_pk }
    }

    /// Get the public key for the traditional DSA
    ///
    /// # Returns
    ///
    /// The public key for the traditional DSA
    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.as_bytes().unwrap().to_vec()
    }

    /// Get the public key for the post-quantum DSA
    ///
    /// # Returns
    ///
    /// The public key for the post-quantum DSA
    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.as_bytes().unwrap().to_vec()
    }
}

#[derive(Debug, Clone, Sequence)]
/// The private key for the composite DSA
pub struct CompositeDsaPrivateKey<'a> {
    /// The private key for the post-quantum DSA. The structure is OneAsymmetricKey
    pq_sk: PrivateKeyInfo<'a>,

    /// The private key for the traditional DSA. The structure is OneAsymmetricKey
    trad_sk: PrivateKeyInfo<'a>,
}

impl<'a> CompositeDsaPrivateKey<'a> {
    /// Create a new composite DSA private key
    ///
    /// # Arguments
    ///
    /// * `pq_sk` - The private key for the post-quantum DSA
    /// * `trad_sk` - The private key for the traditional DSA
    ///
    /// # Returns
    ///
    /// A new composite KEM private key
    pub fn new(pq_sk: PrivateKeyInfo<'a>, trad_sk: PrivateKeyInfo<'a>) -> Self {
        Self { pq_sk, trad_sk }
    }

    /// Get the private key for the post-quantum DSA
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum DSA
    pub fn get_pq_sk(&self) -> &PrivateKeyInfo<'a> {
        &self.pq_sk
    }

    /// Get the private key for the traditional DSA
    ///
    /// # Returns
    ///
    /// The private key for the traditional DSA
    pub fn get_trad_sk(&self) -> &PrivateKeyInfo<'a> {
        &self.trad_sk
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
/// The composite signature value
pub struct CompositeSignatureValue {
    /// The ciphertext for the post-quantum KEM
    pq_sig: OctetString,
    /// The ciphertext for the traditional KEM
    trad_sig: OctetString,
}

impl CompositeSignatureValue {
    /// Create a new composite signature value
    ///
    /// # Arguments
    ///
    /// * `pq_sig` - The signature for the post-quantum DSA
    /// * `trad_ct` - The signature for the traditional DSA
    pub fn new(pq_sig: &[u8], trad_sig: &[u8]) -> Self {
        let pq_sig = OctetString::new(pq_sig).unwrap();
        let trad_sig = OctetString::new(trad_sig).unwrap();
        Self { pq_sig, trad_sig }
    }

    /// Get the signature for the post-quantum DSA
    ///
    /// # Returns
    ///
    /// The signature for the post-quantum DSA
    pub fn get_pq_sig(&self) -> Vec<u8> {
        self.pq_sig.as_bytes().to_vec()
    }

    /// Get the signature for the traditional DSA
    ///
    /// # Returns
    ///
    /// The signature for the traditional DSA
    pub fn get_trad_sig(&self) -> Vec<u8> {
        self.trad_sig.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod test {
    use der::{Decode, Encode};
    use pkcs8::AlgorithmIdentifierRef;

    use super::*;

    #[test]
    fn test_composite_keys() {
        let pq_pk = vec![0x01, 0x02, 0x03];
        let trad_pk = vec![0x04, 0x05, 0x06];
        let c_pk = super::CompositeDsaPublicKey::new(&pq_pk, &trad_pk);
        let pk = c_pk.to_der().unwrap();
        let c_pk = CompositeDsaPublicKey::from_der(&pk).unwrap();
        assert_eq!(c_pk.get_pq_pk(), pq_pk);
        assert_eq!(c_pk.get_trad_pk(), trad_pk);

        let pq_sk = vec![0x01, 0x02, 0x03, 0x04];
        let trad_sk = vec![0x05, 0x06, 0x07, 0x08];

        // Create the OneAsymmetricKey objects for the tradition secret key
        let t_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: "1.2.840.113549.1.1.1".parse().unwrap(),
                parameters: None,
            },
            private_key: &trad_sk,
            public_key: None,
        };

        // Create the OneAsymmetricKey objects for the post-quantum secret key
        let pq_sk_pkcs8 = PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef {
                oid: "1.2.840.113549.1.1.1".parse().unwrap(),
                parameters: None,
            },
            private_key: &pq_sk,
            public_key: None,
        };

        let c_sk = CompositeDsaPrivateKey::new(pq_sk_pkcs8, t_sk_pkcs8);

        let sk = c_sk.to_der().unwrap();

        let c_sk = CompositeDsaPrivateKey::from_der(&sk).unwrap();

        assert_eq!(c_sk.get_pq_sk().private_key, pq_sk);
        assert_eq!(c_sk.get_trad_sk().private_key, trad_sk);
    }
}
