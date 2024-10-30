use crate::dsa::common::config::oids::Oid;
use crate::dsa::common::config::pk_len::PKLen;
use crate::dsa::common::config::sig_len::SigLen;
use crate::dsa::common::config::sk_len::SKLen;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;

// TODO: There could me more info to include for Prehash DSA Info

/// A structure to represent metadata about a DSA
///
/// This is also used to test the correctness of the DSA
#[derive(Clone)]
#[allow(dead_code)]
pub struct PrehashDsaInfo {
    /// The type of DSA
    pub dsa_type: PrehashDsaType,
    /// The length of the public key in bytes (if fixed size, otherwise `None`)
    pub pk_byte_len: Option<usize>,
    /// The length of the secret key in bytes (if fixed size, otherwise `None`)
    pub sk_byte_len: Option<usize>,
    /// The length of the signature in bytes (if fixed size, otherwise `None`)
    pub sig_byte_len: Option<usize>,
    /// The OID of the DSA
    pub oid: String,
}

impl PrehashDsaInfo {
    /// Create a new DSA metadata structure
    ///
    /// # Arguments
    ///
    /// * `dsa_type` - The type of DSA
    ///
    /// # Returns
    ///
    /// A new DSA metadata structure
    pub fn new(dsa_type: PrehashDsaType) -> Self {
        let pk_byte_len = dsa_type.get_pk_len();
        let sk_byte_len = dsa_type.get_sk_len();
        let sig_byte_len = dsa_type.get_sig_len();
        let oid = dsa_type.get_oid();
        PrehashDsaInfo {
            dsa_type,
            pk_byte_len,
            sk_byte_len,
            sig_byte_len,
            oid,
        }
    }
}
