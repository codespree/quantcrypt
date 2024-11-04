use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::config::oids::Oid;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum DsaType {
    // RSA
    Rsa2048PssSha256,
    Rsa2048Pkcs15Sha256,
    Rsa3072PssSha256,
    Rsa3072Pkcs15Sha256,
    Rsa4096PssSha384,
    Rsa4096Pkcs15Sha384,

    // ECDSA
    EcdsaP256SHA256,
    EcdsaP384SHA384,
    EcdsaBrainpoolP256r1SHA256,
    Ed25519,
    Ed448,
    EcdsaBrainpoolP384r1SHA384,
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
