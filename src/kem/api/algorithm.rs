use crate::kem::common::{config::oids::Oid, kem_type::KemType};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
/// The permissible algorithms for the `AlgorithmIdentifier` type.
pub enum KemAlgorithm {
    /// Pure KEMs
    MlKem512,
    MlKem768,
    MlKem1024,

    // The compsite algorithm list is from the latest editor's draft:
    //https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
    MlKem768Rsa2048,
    MlKem768Rsa3072,
    MlKem768Rsa4096,
    MlKem768X25519,
    MlKem768P384,
    MlKem768BrainpoolP256r1,
    MlKem1024P384,
    MlKem1024BrainpoolP384r1,
    MlKem1024X448,
}

impl KemAlgorithm {
    pub(crate) fn all() -> Vec<KemAlgorithm> {
        KemAlgorithm::iter().collect()
    }

    /// Get the corresponding `DsaType` for the algorithm
    pub(crate) fn get_kem_type(&self) -> KemType {
        match self {
            // Pure KEMs
            KemAlgorithm::MlKem512 => KemType::MlKem512,
            KemAlgorithm::MlKem768 => KemType::MlKem768,
            KemAlgorithm::MlKem1024 => KemType::MlKem1024,

            // The compsite algorithm list is from the latest editor's draft:
            //https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
            KemAlgorithm::MlKem768Rsa2048 => KemType::MlKem768Rsa2048,
            KemAlgorithm::MlKem768Rsa3072 => KemType::MlKem768Rsa3072,
            KemAlgorithm::MlKem768Rsa4096 => KemType::MlKem768Rsa4096,
            KemAlgorithm::MlKem768X25519 => KemType::MlKem768X25519,
            KemAlgorithm::MlKem768P384 => KemType::MlKem768P384,
            KemAlgorithm::MlKem768BrainpoolP256r1 => KemType::MlKem768BrainpoolP256r1,
            KemAlgorithm::MlKem1024P384 => KemType::MlKem1024P384,
            KemAlgorithm::MlKem1024BrainpoolP384r1 => KemType::MlKem1024BrainpoolP384r1,
            KemAlgorithm::MlKem1024X448 => KemType::MlKem1024X448,
        }
    }

    /// Check if the algorithm is a composite or pure algorithm
    pub fn is_composite(&self) -> bool {
        !matches!(
            self,
            KemAlgorithm::MlKem512 | KemAlgorithm::MlKem768 | KemAlgorithm::MlKem1024
        )
    }

    /// Get the OID for the algorithm
    ///
    /// # Returns
    ///
    /// The OID for the algorithm
    pub fn get_oid(&self) -> String {
        self.get_kem_type().get_oid()
    }

    pub fn from_oid(oid: &str) -> Option<KemAlgorithm> {
        KemAlgorithm::all()
            .iter()
            .find(|x| x.get_oid() == oid)
            .cloned()
    }
}
