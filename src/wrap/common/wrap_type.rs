use crate::wrap::common::config::oids::Oid;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, PartialEq, EnumIter)]
pub enum WrapType {
    Aes128,
    Aes256,
}

impl WrapType {
    pub fn all() -> Vec<WrapType> {
        WrapType::iter().collect()
    }

    pub fn from_oid(oid: &str) -> Option<WrapType> {
        let all_wrap_types = WrapType::all();
        all_wrap_types
            .into_iter()
            .find(|wrap_type| wrap_type.get_oid() == oid)
    }
}
