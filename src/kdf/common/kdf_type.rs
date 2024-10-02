use crate::kdf::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum KdfType {
    HkdfWithSha256,
    HkdfWithSha512,
    Kmac128,
    Kmac256,
}

impl KdfType {
    pub fn all() -> Vec<KdfType> {
        KdfType::iter().collect()
    }

    pub fn from_oid(oid: &str) -> Option<KdfType> {
        let all_kdf_types = KdfType::all();
        all_kdf_types
            .into_iter()
            .find(|kdf_type| kdf_type.get_oid() == oid)
    }
}
