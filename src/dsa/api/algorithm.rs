use crate::dsa::common::{config::oids::Oid, dsa_type::DsaType, prehash_dsa_type::PrehashDsaType};

use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Clone, Debug, PartialEq, EnumIter, Display, Copy)]
/// The permissible algorithms for the `AlgorithmIdentifier` type.
pub enum DsaAlgorithm {
    // ML DSA Pure
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // ML DSA Prehash
    HashMlDsa44,
    HashMlDsa65,
    HashMlDsa87,

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
    HashMlDsa44Rsa2048PssSha256,
    HashMlDsa44Rsa2048Pkcs15Sha256,
    HashMlDsa44Ed25519Sha512,
    HashMlDsa44EcdsaP256Sha256,
    HashMlDsa65Rsa3072PssSha512,
    HashMlDsa65Rsa3072Pkcs15Sha512,
    HashMlDsa65Rsa4096PssSha512,
    HashMlDsa65Rsa4096Pkcs15Sha512,
    HashMlDsa65EcdsaP384Sha512,
    HashMlDsa65EcdsaBrainpoolP256r1Sha512,
    HashMlDsa65Ed25519Sha512,
    HashMlDsa87EcdsaP384Sha512,
    HashMlDsa87EcdsaBrainpoolP384r1Sha512,
    HashMlDsa87Ed448Sha512,

    // Pure SLH-DSAs
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

    // Prehash SLH-DSAs
    HashSlhDsaSha2_128s,
    HashSlhDsaSha2_128f,
    HashSlhDsaSha2_192s,
    HashSlhDsaSha2_192f,
    HashSlhDsaSha2_256s,
    HashSlhDsaSha2_256f,
    HashSlhDsaShake128s,
    HashSlhDsaShake128f,
    HashSlhDsaShake192s,
    HashSlhDsaShake192f,
    HashSlhDsaShake256s,
    HashSlhDsaShake256f,
}

impl DsaAlgorithm {
    /// Get all DSA algorithms
    pub(crate) fn all() -> Vec<DsaAlgorithm> {
        DsaAlgorithm::iter().collect()
    }

    /// Get the corresponding `DsaType` for the algorithm
    pub(crate) fn get_dsa_type(&self) -> Option<DsaType> {
        None
    }

    /// Get the corresponding `PrehashDsaType` for the algorithm
    pub(crate) fn get_prehash_dsa_type(&self) -> Option<PrehashDsaType> {
        match self {
            // ML DSA
            DsaAlgorithm::MlDsa44 => Some(PrehashDsaType::MlDsa44),
            DsaAlgorithm::MlDsa65 => Some(PrehashDsaType::MlDsa65),
            DsaAlgorithm::MlDsa87 => Some(PrehashDsaType::MlDsa87),

            // Hash ML DSA
            DsaAlgorithm::HashMlDsa44 => Some(PrehashDsaType::HashMlDsa44),
            DsaAlgorithm::HashMlDsa65 => Some(PrehashDsaType::HashMlDsa65),
            DsaAlgorithm::HashMlDsa87 => Some(PrehashDsaType::HashMlDsa87),

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
            DsaAlgorithm::HashMlDsa44Rsa2048PssSha256 => {
                Some(PrehashDsaType::HashMlDsa44Rsa2048PssSha256)
            }
            DsaAlgorithm::HashMlDsa44Rsa2048Pkcs15Sha256 => {
                Some(PrehashDsaType::HashMlDsa44Rsa2048Pkcs15Sha256)
            }
            DsaAlgorithm::HashMlDsa44Ed25519Sha512 => {
                Some(PrehashDsaType::HashMlDsa44Ed25519Sha512)
            }
            DsaAlgorithm::HashMlDsa44EcdsaP256Sha256 => {
                Some(PrehashDsaType::HashMlDsa44EcdsaP256Sha256)
            }
            DsaAlgorithm::HashMlDsa65Rsa3072PssSha512 => {
                Some(PrehashDsaType::HashMlDsa65Rsa3072PssSha512)
            }
            DsaAlgorithm::HashMlDsa65Rsa3072Pkcs15Sha512 => {
                Some(PrehashDsaType::HashMlDsa65Rsa3072Pkcs15Sha512)
            }
            DsaAlgorithm::HashMlDsa65Rsa4096PssSha512 => {
                Some(PrehashDsaType::HashMlDsa65Rsa4096PssSha512)
            }
            DsaAlgorithm::HashMlDsa65Rsa4096Pkcs15Sha512 => {
                Some(PrehashDsaType::HashMlDsa65Rsa4096Pkcs15Sha512)
            }
            DsaAlgorithm::HashMlDsa65EcdsaP384Sha512 => {
                Some(PrehashDsaType::HashMlDsa65EcdsaP384Sha512)
            }
            DsaAlgorithm::HashMlDsa65EcdsaBrainpoolP256r1Sha512 => {
                Some(PrehashDsaType::HashMlDsa65EcdsaBrainpoolP256r1Sha512)
            }
            DsaAlgorithm::HashMlDsa65Ed25519Sha512 => {
                Some(PrehashDsaType::HashMlDsa65Ed25519Sha512)
            }
            DsaAlgorithm::HashMlDsa87EcdsaP384Sha512 => {
                Some(PrehashDsaType::HashMlDsa87EcdsaP384Sha512)
            }
            DsaAlgorithm::HashMlDsa87EcdsaBrainpoolP384r1Sha512 => {
                Some(PrehashDsaType::HashMlDsa87EcdsaBrainpoolP384r1Sha512)
            }
            DsaAlgorithm::HashMlDsa87Ed448Sha512 => Some(PrehashDsaType::HashMlDsa87Ed448Sha512),

            DsaAlgorithm::SlhDsaSha2_128s => Some(PrehashDsaType::SlhDsaSha2_128s),
            DsaAlgorithm::SlhDsaSha2_128f => Some(PrehashDsaType::SlhDsaSha2_128f),
            DsaAlgorithm::SlhDsaSha2_192s => Some(PrehashDsaType::SlhDsaSha2_192s),
            DsaAlgorithm::SlhDsaSha2_192f => Some(PrehashDsaType::SlhDsaSha2_192f),
            DsaAlgorithm::SlhDsaSha2_256s => Some(PrehashDsaType::SlhDsaSha2_256s),
            DsaAlgorithm::SlhDsaSha2_256f => Some(PrehashDsaType::SlhDsaSha2_256f),
            DsaAlgorithm::SlhDsaShake128s => Some(PrehashDsaType::SlhDsaShake128s),
            DsaAlgorithm::SlhDsaShake128f => Some(PrehashDsaType::SlhDsaShake128f),
            DsaAlgorithm::SlhDsaShake192s => Some(PrehashDsaType::SlhDsaShake192s),
            DsaAlgorithm::SlhDsaShake192f => Some(PrehashDsaType::SlhDsaShake192f),
            DsaAlgorithm::SlhDsaShake256s => Some(PrehashDsaType::SlhDsaShake256s),
            DsaAlgorithm::SlhDsaShake256f => Some(PrehashDsaType::SlhDsaShake256f),

            DsaAlgorithm::HashSlhDsaSha2_128s => Some(PrehashDsaType::HashSlhDsaSha2_128s),
            DsaAlgorithm::HashSlhDsaSha2_128f => Some(PrehashDsaType::HashSlhDsaSha2_128f),
            DsaAlgorithm::HashSlhDsaSha2_192s => Some(PrehashDsaType::HashSlhDsaSha2_192s),
            DsaAlgorithm::HashSlhDsaSha2_192f => Some(PrehashDsaType::HashSlhDsaSha2_192f),
            DsaAlgorithm::HashSlhDsaSha2_256s => Some(PrehashDsaType::HashSlhDsaSha2_256s),
            DsaAlgorithm::HashSlhDsaSha2_256f => Some(PrehashDsaType::HashSlhDsaSha2_256f),
            DsaAlgorithm::HashSlhDsaShake128s => Some(PrehashDsaType::HashSlhDsaShake128s),
            DsaAlgorithm::HashSlhDsaShake128f => Some(PrehashDsaType::HashSlhDsaShake128f),
            DsaAlgorithm::HashSlhDsaShake192s => Some(PrehashDsaType::HashSlhDsaShake192s),
            DsaAlgorithm::HashSlhDsaShake192f => Some(PrehashDsaType::HashSlhDsaShake192f),
            DsaAlgorithm::HashSlhDsaShake256s => Some(PrehashDsaType::HashSlhDsaShake256s),
            DsaAlgorithm::HashSlhDsaShake256f => Some(PrehashDsaType::HashSlhDsaShake256f),
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
            DsaAlgorithm::MlDsa44
                | DsaAlgorithm::MlDsa65
                | DsaAlgorithm::MlDsa87
                | DsaAlgorithm::HashMlDsa44
                | DsaAlgorithm::HashMlDsa65
                | DsaAlgorithm::HashMlDsa87
                | DsaAlgorithm::SlhDsaSha2_128s
                | DsaAlgorithm::SlhDsaSha2_128f
                | DsaAlgorithm::SlhDsaSha2_192s
                | DsaAlgorithm::SlhDsaSha2_192f
                | DsaAlgorithm::SlhDsaSha2_256s
                | DsaAlgorithm::SlhDsaSha2_256f
                | DsaAlgorithm::SlhDsaShake128s
                | DsaAlgorithm::SlhDsaShake128f
                | DsaAlgorithm::SlhDsaShake192s
                | DsaAlgorithm::SlhDsaShake192f
                | DsaAlgorithm::SlhDsaShake256s
                | DsaAlgorithm::SlhDsaShake256f
                | DsaAlgorithm::HashSlhDsaSha2_128s
                | DsaAlgorithm::HashSlhDsaSha2_128f
                | DsaAlgorithm::HashSlhDsaSha2_192s
                | DsaAlgorithm::HashSlhDsaSha2_192f
                | DsaAlgorithm::HashSlhDsaSha2_256s
                | DsaAlgorithm::HashSlhDsaSha2_256f
                | DsaAlgorithm::HashSlhDsaShake128s
                | DsaAlgorithm::HashSlhDsaShake128f
                | DsaAlgorithm::HashSlhDsaShake192s
                | DsaAlgorithm::HashSlhDsaShake192f
                | DsaAlgorithm::HashSlhDsaShake256s
                | DsaAlgorithm::HashSlhDsaShake256f
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
