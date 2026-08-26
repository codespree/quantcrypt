use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// The composite public key serialization for both Composite ML-DSA
/// (draft-ietf-lamps-pq-composite-sigs-19 Section 4.1) and Composite ML-KEM
/// (draft-ietf-lamps-pq-composite-kem-15 Section 4.1) is the simple
/// concatenation of the post-quantum public key with the traditional public
/// key: `pqPK || tradPK`. On deserialization the fixed-length post-quantum
/// component is split off the front and the remainder is the traditional key.
#[derive(Debug, Clone)]
/// A public key for a composite DSA / KEM
pub struct CompositePublicKey {
    /// The OID for the composite DSA / KEM
    oid: String,
    /// The public key for the post-quantum DSA / KEM
    pq_pk: Vec<u8>,
    /// The public key for the traditional DSA / KEM
    trad_pk: Vec<u8>,
}

impl CompositePublicKey {
    /// Create a new composite public key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA
    /// * `pq_pk` - The public key for the post-quantum DSA / KEM
    /// * `trad_pk` - The public key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// A new composite DSA / KEM public key
    pub fn new(oid: &str, pq_pk: &[u8], trad_pk: &[u8]) -> Self {
        Self {
            oid: oid.to_string(),
            pq_pk: pq_pk.to_vec(),
            trad_pk: trad_pk.to_vec(),
        }
    }

    /// Get the OID for the composite DSA / KEM
    ///
    /// # Returns
    ///
    /// The OID for the composite DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the public key for the traditional DSA / KEM
    ///
    /// # Returns
    ///
    /// The public key for the traditional DSA / KEM
    pub fn get_trad_pk(&self) -> Vec<u8> {
        self.trad_pk.clone()
    }

    /// Get the public key for the post-quantum DSA / KEM
    ///
    /// # Returns
    ///
    /// The public key for the post-quantum DSA / KEM
    pub fn get_pq_pk(&self) -> Vec<u8> {
        self.pq_pk.clone()
    }

    /// Create a new composite public key from a DER-encoded public key
    ///
    /// # Arguments
    ///
    /// * `der` - The DER-encoded public key
    ///
    /// # Returns
    ///
    /// A new composite public key
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA / KEM
    /// * `der` - The serialized composite public key (`pqPK || tradPK`)
    /// * `pq_len` - The fixed byte length of the post-quantum (ML-DSA / ML-KEM)
    ///   public key, used as the split point.
    pub fn from_der(oid: &str, der: &[u8], pq_len: usize) -> Result<Self> {
        if der.len() < pq_len {
            return Err(QuantCryptError::InvalidPublicKey);
        }
        let (pq_pk, trad_pk) = der.split_at(pq_len);
        Ok(CompositePublicKey::new(oid, pq_pk, trad_pk))
    }

    /// Encode the composite public key as `pqPK || tradPK`.
    ///
    /// # Returns
    ///
    /// The serialized composite public key
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.pq_pk.len() + self.trad_pk.len());
        out.extend_from_slice(&self.pq_pk);
        out.extend_from_slice(&self.trad_pk);
        Ok(out)
    }
}
