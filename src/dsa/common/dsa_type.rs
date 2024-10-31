use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::config::oids::Oid;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum DsaType {
    // RSA
    Rsa2048PssSHA256,
    Rsa2048Pkcs15SHA256,
    Rsa3072PssSHA512,
    Rsa3072Pkcs15SHA512,
    Rsa4096PssSha512,
    Rsa4096Pkcs15Sha512,

    // ECDSA
    EcdsaP256SHA256,
    EcdsaP384SHA384,
    EcdsaBrainpoolP256r1SHA256,
    Ed25519,
    Ed448,
    EcdsaBrainpoolP384r1SHA384,

    // SLH DSA
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

impl DsaType {
    pub fn all() -> Vec<DsaType> {
        DsaType::iter().collect()
    }

    pub fn is_composite(&self) -> bool {
        // Given that all composites are in prehash, this should always be false.
        false
    }

    pub fn from_oid(oid: &str) -> Option<DsaType> {
        let all_dsa_types = DsaType::all();
        all_dsa_types
            .into_iter()
            .find(|dsa_type| dsa_type.get_oid() == oid)
    }
}
