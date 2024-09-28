use der::{asn1::BitString, Sequence};
use pkcs8::spki::AlgorithmIdentifierWithOid;

/// PublicKeyInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     PublicKey   BIT STRING
/// }
#[derive(Debug, Clone, Sequence)]
pub struct PublicKeyInfo {
    pub algorithm: AlgorithmIdentifierWithOid,
    pub public_key: BitString,
}
