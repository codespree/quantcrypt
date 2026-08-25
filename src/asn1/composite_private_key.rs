use der::zeroize::Zeroize;

use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// A private key for a composite DSA / KEM.
///
/// Per draft-ietf-lamps-pq-composite-sigs-19 §4.2 and
/// draft-ietf-lamps-pq-composite-kem-15 §4.2, the composite private key is the
/// raw concatenation of the post-quantum *seed* with the traditional private
/// key: `pqSeed || tradSK`. The post-quantum seed is 32 bytes for ML-DSA and 64
/// bytes (`d || z`) for ML-KEM. The traditional private key is in the encoding
/// appropriate to its algorithm (raw for Ed/X, DER `ECPrivateKey` for ECDSA/ECDH,
/// DER `RSAPrivateKey` for RSA). This byte string is carried directly in the
/// `privateKey` OCTET STRING of the enclosing OneAsymmetricKey.
#[derive(Zeroize)]
pub struct CompositePrivateKey {
    /// The post-quantum seed (32 bytes for ML-DSA, 64 bytes for ML-KEM)
    pq_seed: Vec<u8>,
    /// The traditional private key in its component-appropriate encoding
    trad_sk: Vec<u8>,
    /// The OID for the composite DSA / KEM
    oid: String,
}

impl CompositePrivateKey {
    /// Create a new composite private key from the post-quantum seed and the
    /// (already component-encoded) traditional private key.
    pub fn new(oid: &str, pq_seed: &[u8], trad_sk: &[u8]) -> Self {
        Self {
            pq_seed: pq_seed.to_vec(),
            trad_sk: trad_sk.to_vec(),
            oid: oid.to_string(),
        }
    }

    /// Get the OID for the composite DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the post-quantum seed.
    pub fn get_pq_seed(&self) -> Vec<u8> {
        self.pq_seed.clone()
    }

    /// Get the traditional private key (component-appropriate encoding).
    pub fn get_trad_sk(&self) -> Vec<u8> {
        self.trad_sk.clone()
    }

    /// Deserialize `pqSeed || tradSK`, splitting at the fixed post-quantum seed
    /// length (`pq_seed_len` = 32 for ML-DSA, 64 for ML-KEM).
    pub fn from_der(oid: &str, der: &[u8], pq_seed_len: usize) -> Result<Self> {
        if der.len() < pq_seed_len {
            return Err(QuantCryptError::InvalidPrivateKey);
        }
        let (pq_seed, trad_sk) = der.split_at(pq_seed_len);
        Ok(Self::new(oid, pq_seed, trad_sk))
    }

    /// Serialize as `pqSeed || tradSK`.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.pq_seed.len() + self.trad_sk.len());
        out.extend_from_slice(&self.pq_seed);
        out.extend_from_slice(&self.trad_sk);
        Ok(out)
    }
}
