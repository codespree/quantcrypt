use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::config::oids::Oid;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum PrehashDsaType {
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

impl PrehashDsaType {
    pub fn all() -> Vec<PrehashDsaType> {
        PrehashDsaType::iter().collect()
    }

    pub fn is_composite(&self) -> bool {
        !matches!(self, PrehashDsaType::MlDsa44 | PrehashDsaType::MlDsa65 | PrehashDsaType::MlDsa87)
    }

    pub fn from_oid(oid: &str) -> Option<PrehashDsaType> {
        let all_dsa_types = PrehashDsaType::all();
        all_dsa_types
            .into_iter()
            .find(|dsa_type| dsa_type.get_oid() == oid)
    }
}
