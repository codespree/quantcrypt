use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// The composite ciphertext value.
///
/// Per draft-ietf-lamps-pq-composite-kem-15 Section 4.3, the composite
/// ciphertext is the simple concatenation of the fixed-length ML-KEM ciphertext
/// with the traditional ciphertext: `mlkemCT || tradCT`. On deserialization the
/// fixed-length ML-KEM ciphertext is split off the front (its length is
/// determined by the ML-KEM parameter set of the composite algorithm) and the
/// remainder is the traditional ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeCiphertextValue {
    /// The ciphertext for the post-quantum KEM
    pq_ct: Vec<u8>,
    /// The ciphertext for the traditional KEM
    trad_ct: Vec<u8>,
}

impl CompositeCiphertextValue {
    /// Create a new composite ciphertext value
    ///
    /// # Arguments
    ///
    /// * `pq_ct` - The ciphertext for the post-quantum KEM
    /// * `trad_ct` - The ciphertext for the traditional KEM
    pub fn new(pq_ct: &[u8], trad_ct: &[u8]) -> Self {
        Self {
            pq_ct: pq_ct.to_vec(),
            trad_ct: trad_ct.to_vec(),
        }
    }

    /// Get the ciphertext for the post-quantum KEM
    pub fn get_pq_ct(&self) -> Vec<u8> {
        self.pq_ct.clone()
    }

    /// Get the ciphertext for the traditional KEM
    pub fn get_trad_ct(&self) -> Vec<u8> {
        self.trad_ct.clone()
    }

    /// Serialize as `mlkemCT || tradCT`.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.pq_ct.len() + self.trad_ct.len());
        out.extend_from_slice(&self.pq_ct);
        out.extend_from_slice(&self.trad_ct);
        Ok(out)
    }

    /// Deserialize `mlkemCT || tradCT`, splitting at the fixed ML-KEM ciphertext
    /// length `pq_ct_len`.
    pub fn from_der(der: &[u8], pq_ct_len: usize) -> Result<Self> {
        if der.len() < pq_ct_len {
            return Err(QuantCryptError::InvalidCiphertext);
        }
        let (pq_ct, trad_ct) = der.split_at(pq_ct_len);
        Ok(Self::new(pq_ct, trad_ct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_ciphertext_value() {
        let pq_bytes: Vec<u8> = vec![4, 5, 6];
        let trad_bytes: Vec<u8> = vec![0, 1, 2];

        let composite_ciphertext_value = CompositeCiphertextValue::new(&pq_bytes, &trad_bytes);

        let encoded = composite_ciphertext_value.to_der().unwrap();
        // Raw concatenation: mlkemCT || tradCT.
        assert_eq!(encoded, vec![4, 5, 6, 0, 1, 2]);

        // Split at the ML-KEM (pq) ciphertext length.
        let decoded = CompositeCiphertextValue::from_der(&encoded, pq_bytes.len()).unwrap();
        assert_eq!(decoded.get_trad_ct(), trad_bytes);
        assert_eq!(decoded.get_pq_ct(), pq_bytes);
    }
}
