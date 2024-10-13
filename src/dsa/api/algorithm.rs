use crate::dsa::common::{config::oids::Oid, dsa_type::DsaType};

use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Clone, Debug, PartialEq, EnumIter, Display, Copy)]
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

    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_128s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_128f,
    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_192s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_192f,
    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_256s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaSha2_256f,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake128s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake128f,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake192s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake192f,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake256s,
    #[cfg(not(feature = "ipd"))]
    SlhDsaShake256f,
}

impl DsaAlgorithm {
    /// Get all DSA algorithms
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
            DsaAlgorithm::MlDsa87Ed448SHA512 => DsaType::MlDsa87Ed448SHA512,

            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_128s => DsaType::SlhDsaSha2_128s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_128f => DsaType::SlhDsaSha2_128f,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_192s => DsaType::SlhDsaSha2_192s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_192f => DsaType::SlhDsaSha2_192f,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_256s => DsaType::SlhDsaSha2_256s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaSha2_256f => DsaType::SlhDsaSha2_256f,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake128s => DsaType::SlhDsaShake128s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake128f => DsaType::SlhDsaShake128f,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake192s => DsaType::SlhDsaShake192s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake192f => DsaType::SlhDsaShake192f,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake256s => DsaType::SlhDsaShake256s,
            #[cfg(not(feature = "ipd"))]
            DsaAlgorithm::SlhDsaShake256f => DsaType::SlhDsaShake256f,
        }
    }

    /// Check if the algorithm is a composite or pure algorithm
    ///
    /// # Returns
    ///
    /// True if the algorithm is a composite algorithm, false otherwise
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

    /// Get the DSA algorithm from an OID
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID of the DSA algorithm
    ///
    /// # Returns
    ///
    /// The DSA algorithm or None if the OID is not found
    pub fn from_oid(oid: &str) -> Option<DsaAlgorithm> {
        DsaAlgorithm::all()
            .iter()
            .find(|x| x.get_oid() == oid)
            .cloned()
    }
}
