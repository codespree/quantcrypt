use der::asn1::OctetString;
use der_derive::Sequence;

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
