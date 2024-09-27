use crate::asn1::composite_private_key::CompositePrivateKey;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

// Implement clone
#[derive(Clone)]
/// A raw public key for use with the certificate builder
pub struct RawPrivateKey {
    /// The OID for the DSA / KEM
    oid: String,
    /// The key material
    key: Vec<u8>,
}

impl RawPrivateKey {
    pub fn from_composite_private_key(composite_private_key: &CompositePrivateKey) -> Result<Self> {
        Ok(Self {
            oid: composite_private_key.get_oid().to_string(),
            key: composite_private_key.to_der()?,
        })
    }

    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    pub fn get_key(&self) -> &[u8] {
        &self.key
    }
}
