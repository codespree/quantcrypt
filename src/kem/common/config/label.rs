use crate::kem::common::kem_type::KemType;

/// A trait to get the KEM Combiner Label for a Composite ML-KEM algorithm, as
/// defined in draft-ietf-lamps-pq-composite-kem-15 Section 7 ("KEM Combiner
/// Labels").
///
/// The Label is a fixed per-algorithm octet string mixed into the SHA3-256 KEM
/// combiner (`ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`)
/// to bind the derived shared secret to the specific composite algorithm.
pub trait CompositeLabel {
    /// Get the KEM Combiner Label bytes, or `None` if the algorithm is not a
    /// composite (pure ML-KEM / traditional KEMs have no Label).
    fn get_label(&self) -> Option<Vec<u8>>;
}

impl CompositeLabel for KemType {
    fn get_label(&self) -> Option<Vec<u8>> {
        let label: &[u8] = match self {
            KemType::MlKem768Rsa2048 => b"MLKEM768-RSAOAEP2048",
            KemType::MlKem768Rsa3072 => b"MLKEM768-RSAOAEP3072",
            KemType::MlKem768Rsa4096 => b"MLKEM768-RSAOAEP4096",
            // id-MLKEM768-X25519 uses the non-alphanumeric label "\.//^\",
            // provided in the draft only in hex to avoid transcription errors.
            KemType::MlKem768X25519 => &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
            KemType::MlKem768P256 => b"MLKEM768-P256",
            KemType::MlKem768P384 => b"MLKEM768-P384",
            KemType::MlKem768BrainpoolP256r1 => b"MLKEM768-BP256",
            KemType::MlKem1024Rsa3072 => b"MLKEM1024-RSAOAEP3072",
            KemType::MlKem1024P384 => b"MLKEM1024-P384",
            KemType::MlKem1024BrainpoolP384r1 => b"MLKEM1024-BP384",
            KemType::MlKem1024X448 => b"MLKEM1024-X448",
            KemType::MlKem1024P521 => b"MLKEM1024-P521",
            // Pure ML-KEM, traditional KEMs, and X-Wing are not composites.
            _ => return None,
        };
        Some(label.to_vec())
    }
}
