use std::error;

use der::Document;
use pkcs8::EncodePublicKey;

use crate::asn1::composite_public_key::CompositePublicKey;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

// Implement clone
#[derive(Clone)]
/// A raw public key for use with the certificate builder
pub struct RawPublicKey {
    /// The OID for the DSA / KEM
    oid: String,
    /// The key material
    key: Vec<u8>,
}

impl RawPublicKey {
    pub fn from_composite_public_key(composite_public_key: &CompositePublicKey) -> Result<Self> {
        Ok(Self {
            oid: composite_public_key.get_oid().to_string(),
            key: composite_public_key.to_der()?,
        })
    }

    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    pub fn get_key(&self) -> &[u8] {
        &self.key
    }
}

impl EncodePublicKey for RawPublicKey {
    fn to_public_key_der(&self) -> std::result::Result<Document, pkcs8::spki::Error> {
        let doc = Document::try_from(self.key.to_vec())?;
        Ok(doc)
    }
}
