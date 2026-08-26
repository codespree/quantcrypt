use crate::QuantCryptError;

type Result<T> = std::result::Result<T, QuantCryptError>;

/// The composite signature value.
///
/// Per draft-ietf-lamps-pq-composite-sigs-19 Section 4.3, the composite
/// signature is the simple concatenation of the fixed-length ML-DSA signature
/// with the traditional signature: `mldsaSig || tradSig`. On deserialization
/// the fixed-length ML-DSA signature is split off the front (its length is
/// determined by the ML-DSA parameter set of the composite algorithm) and the
/// remainder is the traditional signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSignatureValue {
    /// The signature for the post-quantum (ML-DSA) component
    pq_sig: Vec<u8>,
    /// The signature for the traditional component
    trad_sig: Vec<u8>,
}

impl CompositeSignatureValue {
    /// Create a new composite signature value
    ///
    /// # Arguments
    ///
    /// * `pq_sig` - The signature for the post-quantum DSA
    /// * `trad_sig` - The signature for the traditional DSA
    pub fn new(pq_sig: &[u8], trad_sig: &[u8]) -> Self {
        Self {
            pq_sig: pq_sig.to_vec(),
            trad_sig: trad_sig.to_vec(),
        }
    }

    /// Get the signature for the post-quantum DSA
    pub fn get_pq_sig(&self) -> Vec<u8> {
        self.pq_sig.clone()
    }

    /// Get the signature for the traditional DSA
    pub fn get_trad_sig(&self) -> Vec<u8> {
        self.trad_sig.clone()
    }

    /// Serialize as `mldsaSig || tradSig`.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.pq_sig.len() + self.trad_sig.len());
        out.extend_from_slice(&self.pq_sig);
        out.extend_from_slice(&self.trad_sig);
        Ok(out)
    }

    /// Deserialize `mldsaSig || tradSig`, splitting at the fixed ML-DSA
    /// signature length `pq_sig_len`.
    pub fn from_der(der: &[u8], pq_sig_len: usize) -> Result<Self> {
        if der.len() < pq_sig_len {
            return Err(QuantCryptError::InvalidSignature);
        }
        let (pq_sig, trad_sig) = der.split_at(pq_sig_len);
        Ok(Self::new(pq_sig, trad_sig))
    }
}
