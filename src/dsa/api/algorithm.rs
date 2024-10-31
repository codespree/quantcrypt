use crate::dsa::common::{config::oids::Oid, dsa_type::DsaType, prehash_dsa_type::PrehashDsaType};

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
    MlDsa44Rsa2048Pss,
    MlDsa44Rsa2048Pkcs15,
    MlDsa44Ed25519,
    MlDsa44EcdsaP256,
    MlDsa65Rsa3072Pss,
    MlDsa65Rsa3072Pkcs15,
    MlDsa65EcdsaP384,
    MlDsa65EcdsaBrainpoolP256r1,
    MlDsa65Ed25519,
    MlDsa87EcdsaP384,
    MlDsa87EcdsaBrainpoolP384r1,
    MlDsa87Ed448,
    MlDsa65Rsa4096Pss,
    MlDsa65Rsa4096Pkcs15,

    // Composite DSAs Prehash
    MlDsa44Rsa2048PssSha256,
    MlDsa44Rsa2048Pkcs15Sha256,
    MlDsa44Ed25519Sha512,
    MlDsa44EcdsaP256Sha256,
    MlDsa65Rsa3072PssSha512,
    MlDsa65Rsa3072Pkcs15Sha512,
    MlDsa65Rsa4096PssSha512,
    MlDsa65Rsa4096Pkcs15Sha512,
    MlDsa65EcdsaP384Sha512,
    MlDsa65EcdsaBrainpoolP256r1Sha512,
    MlDsa65Ed25519Sha512,
    MlDsa87EcdsaP384Sha512,
    MlDsa87EcdsaBrainpoolP384r1Sha512,
    MlDsa87Ed448Sha512,

    // Pure DSAs
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

impl DsaAlgorithm {
    /// Get all DSA algorithms
    pub(crate) fn all() -> Vec<DsaAlgorithm> {
        DsaAlgorithm::iter().collect()
    }

    /// Get the corresponding `DsaType` for the algorithm
    pub(crate) fn get_dsa_type(&self) -> Option<DsaType> {
        match self {
            DsaAlgorithm::SlhDsaSha2_128s => Some(DsaType::SlhDsaSha2_128s),
            DsaAlgorithm::SlhDsaSha2_128f => Some(DsaType::SlhDsaSha2_128f),
            DsaAlgorithm::SlhDsaSha2_192s => Some(DsaType::SlhDsaSha2_192s),
            DsaAlgorithm::SlhDsaSha2_192f => Some(DsaType::SlhDsaSha2_192f),
            DsaAlgorithm::SlhDsaSha2_256s => Some(DsaType::SlhDsaSha2_256s),
            DsaAlgorithm::SlhDsaSha2_256f => Some(DsaType::SlhDsaSha2_256f),
            DsaAlgorithm::SlhDsaShake128s => Some(DsaType::SlhDsaShake128s),
            DsaAlgorithm::SlhDsaShake128f => Some(DsaType::SlhDsaShake128f),
            DsaAlgorithm::SlhDsaShake192s => Some(DsaType::SlhDsaShake192s),
            DsaAlgorithm::SlhDsaShake192f => Some(DsaType::SlhDsaShake192f),
            DsaAlgorithm::SlhDsaShake256s => Some(DsaType::SlhDsaShake256s),
            DsaAlgorithm::SlhDsaShake256f => Some(DsaType::SlhDsaShake256f),
            _ => None,
        }
    }

    /// Get the corresponding `PrehashDsaType` for the algorithm
    pub(crate) fn get_prehash_dsa_type(&self) -> Option<PrehashDsaType> {
        match self {
            // ML DSA
            DsaAlgorithm::MlDsa44 => Some(PrehashDsaType::MlDsa44),
            DsaAlgorithm::MlDsa65 => Some(PrehashDsaType::MlDsa65),
            DsaAlgorithm::MlDsa87 => Some(PrehashDsaType::MlDsa87),

            // Composite DSAs
            DsaAlgorithm::MlDsa44Rsa2048Pss => Some(PrehashDsaType::MlDsa44Rsa2048Pss),
            DsaAlgorithm::MlDsa44Rsa2048Pkcs15 => Some(PrehashDsaType::MlDsa44Rsa2048Pkcs15),
            DsaAlgorithm::MlDsa44Ed25519 => Some(PrehashDsaType::MlDsa44Ed25519),
            DsaAlgorithm::MlDsa44EcdsaP256 => Some(PrehashDsaType::MlDsa44EcdsaP256),
            DsaAlgorithm::MlDsa65Rsa3072Pss => Some(PrehashDsaType::MlDsa65Rsa3072Pss),
            DsaAlgorithm::MlDsa65Rsa3072Pkcs15 => Some(PrehashDsaType::MlDsa65Rsa3072Pkcs15),
            DsaAlgorithm::MlDsa65EcdsaP384 => Some(PrehashDsaType::MlDsa65EcdsaP384),
            DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1 => {
                Some(PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1)
            }
            DsaAlgorithm::MlDsa65Ed25519 => Some(PrehashDsaType::MlDsa65Ed25519),
            DsaAlgorithm::MlDsa87EcdsaP384 => Some(PrehashDsaType::MlDsa87EcdsaP384),
            DsaAlgorithm::MlDsa87EcdsaBrainpoolP384r1 => {
                Some(PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1)
            }
            DsaAlgorithm::MlDsa87Ed448 => Some(PrehashDsaType::MlDsa87Ed448),
            DsaAlgorithm::MlDsa65Rsa4096Pss => Some(PrehashDsaType::MlDsa65Rsa4096Pss),
            DsaAlgorithm::MlDsa65Rsa4096Pkcs15 => Some(PrehashDsaType::MlDsa65Rsa4096Pkcs15),

            // Composite DSAs Prehash
            DsaAlgorithm::MlDsa44Rsa2048PssSha256 => Some(PrehashDsaType::MlDsa44Rsa2048PssSha256),
            DsaAlgorithm::MlDsa44Rsa2048Pkcs15Sha256 => {
                Some(PrehashDsaType::MlDsa44Rsa2048Pkcs15Sha256)
            }
            DsaAlgorithm::MlDsa44Ed25519Sha512 => Some(PrehashDsaType::MlDsa44Ed25519Sha512),
            DsaAlgorithm::MlDsa44EcdsaP256Sha256 => Some(PrehashDsaType::MlDsa44EcdsaP256Sha256),
            DsaAlgorithm::MlDsa65Rsa3072PssSha512 => Some(PrehashDsaType::MlDsa65Rsa3072PssSha512),
            DsaAlgorithm::MlDsa65Rsa3072Pkcs15Sha512 => {
                Some(PrehashDsaType::MlDsa65Rsa3072Pkcs15Sha512)
            }
            DsaAlgorithm::MlDsa65Rsa4096PssSha512 => Some(PrehashDsaType::MlDsa65Rsa4096PssSha512),
            DsaAlgorithm::MlDsa65Rsa4096Pkcs15Sha512 => {
                Some(PrehashDsaType::MlDsa65Rsa4096Pkcs15Sha512)
            }
            DsaAlgorithm::MlDsa65EcdsaP384Sha512 => Some(PrehashDsaType::MlDsa65EcdsaP384Sha512),
            DsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1Sha512 => {
                Some(PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1Sha512)
            }
            DsaAlgorithm::MlDsa65Ed25519Sha512 => Some(PrehashDsaType::MlDsa65Ed25519Sha512),
            DsaAlgorithm::MlDsa87EcdsaP384Sha512 => Some(PrehashDsaType::MlDsa87EcdsaP384Sha512),
            DsaAlgorithm::MlDsa87EcdsaBrainpoolP384r1Sha512 => {
                Some(PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1Sha512)
            }
            DsaAlgorithm::MlDsa87Ed448Sha512 => Some(PrehashDsaType::MlDsa87Ed448Sha512),
            _ => None,
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
        if let Some(dsa_type) = self.get_dsa_type() {
            dsa_type.get_oid()
        } else {
            self.get_prehash_dsa_type().unwrap().get_oid()
        }
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
