use crate::cea::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
#[allow(clippy::enum_variant_names)]
pub enum CeaType {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    Aes128CbcPad,
    Aes192CbcPad,
    Aes256CbcPad,
}

impl CeaType {
    pub fn all() -> Vec<CeaType> {
        CeaType::iter().collect()
    }

    pub fn from_oid(oid: &str) -> Option<CeaType> {
        let all_cae_types = CeaType::all();
        all_cae_types
            .into_iter()
            .find(|cae_type| cae_type.get_oid() == oid)
    }
}
