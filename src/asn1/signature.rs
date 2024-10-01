use der::asn1::BitString;
use pkcs8::spki::SignatureBitStringEncoding;

/// Struct representing DSA signatures
pub struct DsaSignature(pub Vec<u8>);

impl SignatureBitStringEncoding for DsaSignature {
    fn to_bitstring(&self) -> Result<BitString, der::Error> {
        BitString::from_bytes(&self.0)
    }
}
