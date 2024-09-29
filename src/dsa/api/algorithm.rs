use crate::dsa::common::{config::oids::Oid, dsa_type::DsaType};

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
/// The permissible algorithms for the `AlgorithmIdentifier` type.
pub enum DsaAlgorithm {
    // ML DSA
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // Composite DSAs
    MlDsa44Rsa2048PssSha256,
    MlDsa44Rsa2048Pkcs15Sha256,
    MlDsa44Ed25519SHA512,
    MlDsa44EcdsaP256SHA256,
    MlDsa44EcdsaBrainpoolP256r1SHA256,
    MlDsa65Rsa3072PssSHA512,
    MlDsa65Rsa3072Pkcs15SHA512,
    MlDsa65EcdsaP256SHA512,
    MlDsa65EcdsaBrainpoolP256r1SHA512,
    MlDsa65Ed25519SHA512,
    MlDsa87EcdsaP384SHA512,
    MlDsa87EcdsaBrainpoolP384r1SHA512,
    MlDsa87Ed448SHA512,
}

impl DsaAlgorithm {
    pub(crate) fn all() -> Vec<DsaAlgorithm> {
        DsaAlgorithm::iter().collect()
    }

    /// Get the corresponding `DsaType` for the algorithm
    pub(crate) fn get_dsa_type(&self) -> DsaType {
        match self {
            // Pure DSAs
            DsaAlgorithm::MlDsa44 => DsaType::MlDsa44,
            DsaAlgorithm::MlDsa65 => DsaType::MlDsa65,
            DsaAlgorithm::MlDsa87 => DsaType::MlDsa87,

            // Composite DSAs
            DsaAlgorithm::MlDsa44Rsa2048PssSha256 => DsaType::MlDsa44Rsa2048PssSha256,
            DsaAlgorithm::MlDsa44Rsa2048Pkcs15Sha256 => DsaType::MlDsa44Rsa2048Pkcs15Sha256,
            DsaAlgorithm::MlDsa44Ed25519SHA512 => DsaType::MlDsa44Ed25519SHA512,
            DsaAlgorithm::MlDsa44EcdsaP256SHA256 => DsaType::MlDsa44EcdsaP256SHA256,
            DsaAlgorithm::MlDsa44EcdsaBrainpoolP256r1SHA256 => {
                DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256
            }
            DsaAlgorithm::MlDsa65Rsa3072PssSHA512 => DsaType::MlDsa65Rsa3072PssSHA512,
            DsaAlgorithm::MlDsa65Rsa3072Pkcs15SHA512 => DsaType::MlDsa65Rsa3072Pkcs15SHA512,
            DsaAlgorithm::MlDsa65EcdsaP256SHA512 => DsaType::MlDsa65EcdsaP256SHA512,
            DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1SHA512 => {
                DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512
            }
            DsaAlgorithm::MlDsa65Ed25519SHA512 => DsaType::MlDsa65Ed25519SHA512,
            DsaAlgorithm::MlDsa87EcdsaP384SHA512 => DsaType::MlDsa87EcdsaP384SHA512,
            DsaAlgorithm::MlDsa87EcdsaBrainpoolP384r1SHA512 => {
                DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512
            }
            DsaAlgorithm::MlDsa87Ed448SHA512 => DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512,
        }
    }

    /// Check if the algorithm is a composite or pure algorithm
    pub fn is_composite(&self) -> bool {
        !matches!(
            self,
            DsaAlgorithm::MlDsa44 | DsaAlgorithm::MlDsa65 | DsaAlgorithm::MlDsa87
        )
    }

    /// Get the OID for the algorithm
    ///
    /// # Returns
    ///
    /// The OID for the algorithm
    pub fn get_oid(&self) -> String {
        self.get_dsa_type().get_oid()
    }

    pub fn from_oid(oid: &str) -> Option<DsaAlgorithm> {
        DsaAlgorithm::all()
            .iter()
            .find(|x| x.get_oid() == oid)
            .cloned()
    }
}
