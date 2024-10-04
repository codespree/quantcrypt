use crate::wrap::common::config::oids::Oid;
use crate::wrap::common::wrap_info::WrapInfo;
use crate::{wrap::common::wrap_type::WrapType, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Wrap {
    fn new(wrap_type: WrapType) -> Result<Self>
    where
        Self: Sized;

    fn wrap(&self, wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<Vec<u8>>;

    fn unwrap(&self, wrapping_key: &[u8], key_to_unwrap: &[u8]) -> Result<Vec<u8>>;

    fn get_wrap_info(&self) -> WrapInfo;

    fn new_from_oid(oid: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let all_wrap_types = WrapType::all();
        for wrap_type in all_wrap_types {
            if wrap_type.get_oid() == oid {
                let wrap = Self::new(wrap_type)?;
                return Ok(wrap);
            }
        }
        Err(QuantCryptError::InvalidOid)
    }
}
