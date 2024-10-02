use crate::wrap::common::wrap_info::WrapInfo;
use crate::{wrap::common::wrap_type::WrapType, QuantCryptError};

type Result<T> = std::result::Result<T, QuantCryptError>;

pub trait Wrap {
    fn new(wrap_type: WrapType) -> Result<Self>
    where
        Self: Sized;

    fn wrap(&self, key_to_wrap: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>>;

    fn unwrap(&self, wrapped_key: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>>;

    fn get_wrap_info(&self) -> WrapInfo;
}
