use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::kem::common::config::oids::Oid;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum KemType {
    /// NIST P-256 key encapsulation mechanism
    P256,
    /// NIST P-384 key encapsulation mechanism
    P384,
    /// X25519 key encapsulation mechanism
    X25519,
    /// BrainpoolP256r1 key encapsulation mechanism
    BrainpoolP256r1,
    /// BrainpoolP384r1 key encapsulation mechanism
    BrainpoolP384r1,
    /// X448 key encapsulation mechanism
    X448,
    /// RSA 2048 key encapsulation mechanism
    RsaOAEP2048,
    /// RSA 3072 key encapsulation mechanism
    RsaOAEP3072,
    /// RSA 3072 key encapsulation mechanism
    RsaOAEP4096,
    /// MlKem512 key encapsulation mechanism
    MlKem512,
    /// MlKem768 key encapsulation mechanism
    MlKem768,
    /// MlKem1024 key encapsulation mechanism
    MlKem1024,

    // The composite algorithm list from the old version
    /// id-MLKEM512-ECDH-P256
    MlKem512P256,
    /// id-MLKEM512-ECDH-brainpoolP256r1
    MlKem512BrainpoolP256r1,
    /// id-MLKEM512-X25519
    MlKem512X25519,
    /// id-MLKEM512-RSA2048
    MlKem512Rsa2048,
    /// id-MLKEM512-RSA3072
    MlKem512Rsa3072,
    /// id-MLKEM768-ECDH-P256
    MlKem768P256,

    // The compsite algorithm list is from the latest editor's draft:
    //https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
    /// id-MLKEM768-RSA2048
    MlKem768Rsa2048,
    /// id-MLKEM768-RSA3072
    MlKem768Rsa3072,
    /// id-MLKEM768-RSA4096
    MlKem768Rsa4096,
    /// id-MLKEM768-X25519
    MlKem768X25519,
    /// id-MLKEM768-ECDH-P384
    MlKem768P384,
    /// id-MLKEM768-ECDH-brainpoolP256r1
    MlKem768BrainpoolP256r1,
    /// id-MLKEM1024-ECDH-P384
    MlKem1024P384,
    /// id-MLKEM1024-ECDH-brainpoolP384r1
    MlKem1024BrainpoolP384r1,
    /// id-MLKEM1024-X448
    MlKem1024X448,
    XWing,
}

impl KemType {
    pub fn all() -> Vec<KemType> {
        KemType::iter().collect()
    }

    pub fn is_composite(&self) -> bool {
        !matches!(
            self,
            KemType::MlKem512 | KemType::MlKem768 | KemType::MlKem1024
        )
    }

    pub fn from_oid(oid: &str) -> Option<KemType> {
        let all_kem_types = KemType::all();
        all_kem_types
            .into_iter()
            .find(|kem_type| kem_type.get_oid() == oid)
    }
}
