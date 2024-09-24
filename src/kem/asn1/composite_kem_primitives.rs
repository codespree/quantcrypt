use der::asn1::OctetString;
use der_derive::Sequence;

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
