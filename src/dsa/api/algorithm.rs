use crate::dsa::common::{config::oids::Oid, dsa_type::DsaType, prehash_dsa_type::PrehashDsaType};

use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Clone, Debug, PartialEq, EnumIter, Display, Copy)]
/// The permissible algorithms for the `AlgorithmIdentifier` type.
pub enum DsaAlgorithm {
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
    pub(crate) fn get_dsa_type(&self) -> DsaType {
        match self {
            DsaAlgorithm::SlhDsaSha2_128s => DsaType::SlhDsaSha2_128s,
            DsaAlgorithm::SlhDsaSha2_128f => DsaType::SlhDsaSha2_128f,
            DsaAlgorithm::SlhDsaSha2_192s => DsaType::SlhDsaSha2_192s,
            DsaAlgorithm::SlhDsaSha2_192f => DsaType::SlhDsaSha2_192f,
            DsaAlgorithm::SlhDsaSha2_256s => DsaType::SlhDsaSha2_256s,
            DsaAlgorithm::SlhDsaSha2_256f => DsaType::SlhDsaSha2_256f,
            DsaAlgorithm::SlhDsaShake128s => DsaType::SlhDsaShake128s,
            DsaAlgorithm::SlhDsaShake128f => DsaType::SlhDsaShake128f,
            DsaAlgorithm::SlhDsaShake192s => DsaType::SlhDsaShake192s,
            DsaAlgorithm::SlhDsaShake192f => DsaType::SlhDsaShake192f,
            DsaAlgorithm::SlhDsaShake256s => DsaType::SlhDsaShake256s,
            DsaAlgorithm::SlhDsaShake256f => DsaType::SlhDsaShake256f,
        }
    }

    /// Check if the algorithm is a composite or pure algorithm
    ///
    /// # Returns
    ///
    /// True if the algorithm is a composite algorithm, false otherwise
    pub fn is_composite(&self) -> bool {
        // !matches!(
        //     self,
        //     DsaAlgorithm::MlDsa44 | DsaAlgorithm::MlDsa65 | DsaAlgorithm::MlDsa87
        // )
        false
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

#[derive(Clone, Debug, PartialEq, EnumIter, Display, Copy)]
pub enum PrehashDsaAlgorithm {
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
}

impl PrehashDsaAlgorithm {
    /// Get all DSA algorithms
    pub(crate) fn all() -> Vec<PrehashDsaAlgorithm> {
        PrehashDsaAlgorithm::iter().collect()
    }

    /// Get the corresponding `DsaType` for the algorithm
    pub(crate) fn get_dsa_type(&self) -> PrehashDsaType {
        match self {
            // Pure DSAs
            PrehashDsaAlgorithm::MlDsa44 => PrehashDsaType::MlDsa44,
            PrehashDsaAlgorithm::MlDsa65 => PrehashDsaType::MlDsa65,
            PrehashDsaAlgorithm::MlDsa87 => PrehashDsaType::MlDsa87,

            // Composite DSAs
            PrehashDsaAlgorithm::MlDsa44Rsa2048Pss => PrehashDsaType::MlDsa44Rsa2048Pss,
            PrehashDsaAlgorithm::MlDsa44Rsa2048Pkcs15 => PrehashDsaType::MlDsa44Rsa2048Pkcs15,
            PrehashDsaAlgorithm::MlDsa44Ed25519 => PrehashDsaType::MlDsa44Ed25519,
            PrehashDsaAlgorithm::MlDsa44EcdsaP256 => PrehashDsaType::MlDsa44EcdsaP256,
            PrehashDsaAlgorithm::MlDsa65Rsa3072Pss => PrehashDsaType::MlDsa65Rsa3072Pss,
            PrehashDsaAlgorithm::MlDsa65Rsa3072Pkcs15 => PrehashDsaType::MlDsa65Rsa3072Pkcs15,
            PrehashDsaAlgorithm::MlDsa65EcdsaP384 => PrehashDsaType::MlDsa65EcdsaP384, //TODO: newly added, check manually 
            PrehashDsaAlgorithm::MlDsa65EcdsaBrainpoolP256r1 => {
                PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1
            }
            PrehashDsaAlgorithm::MlDsa65Ed25519 => PrehashDsaType::MlDsa65Ed25519,
            PrehashDsaAlgorithm::MlDsa87EcdsaP384 => PrehashDsaType::MlDsa87EcdsaP384,
            PrehashDsaAlgorithm::MlDsa87EcdsaBrainpoolP384r1 => {
                PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1
            }
            PrehashDsaAlgorithm::MlDsa87Ed448 => PrehashDsaType::MlDsa87Ed448,
            PrehashDsaAlgorithm::MlDsa65Rsa4096Pss => PrehashDsaType::MlDsa65Rsa4096Pss, //TODO: newly added, check manually 
            PrehashDsaAlgorithm::MlDsa65Rsa4096Pkcs15=> PrehashDsaType::MlDsa65Rsa4096Pkcs15, //TODO: newly added, check manually 
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
            PrehashDsaAlgorithm::MlDsa44 | PrehashDsaAlgorithm::MlDsa65 | PrehashDsaAlgorithm::MlDsa87
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
