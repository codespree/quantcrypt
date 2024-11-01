use der::asn1::OctetString;
use der::zeroize::Zeroize;
use der::{Decode, Encode};
use der_derive::Sequence;
use pkcs8::PrivateKeyInfo;

use crate::QuantCryptError;

use super::asn_util::is_dsa_oid;

type Result<T> = std::result::Result<T, QuantCryptError>;

#[derive(Debug, Clone, Sequence)]
/// CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
/// CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
struct CompositeKEMPrivateKey<'a> {
    pq_sk: PrivateKeyInfo<'a>,
    trad_sk: PrivateKeyInfo<'a>,
}

#[derive(Debug, Clone, Sequence)]
/// CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OctetString
struct CompositeSignaturePrivateKey {
    pq_sk: OctetString,
    trad_sk: OctetString,
}

/// A private key for a composite DSA / KEM
#[derive(Zeroize)]
pub struct CompositePrivateKey {
    /// The private key for the post-quantum DSA / KEM
    pq_sk_der: Vec<u8>,
    /// The private key for the traditional DSA / KEM
    trad_sk_der: Vec<u8>,
    /// The OID for the composite DSA / KEM
    oid: String,
}

impl CompositePrivateKey {
    /// Create a new composite KEM private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite KEM
    /// * `pq_sk` - The private key for the post-quantum KEM
    /// * `trad_sk` - The private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// A new composite KEM private key
    pub fn new_kem(
        oid: &str,
        pq_sk: &PrivateKeyInfo<'_>,
        trad_sk: &PrivateKeyInfo<'_>,
    ) -> Result<Self> {
        let pq_sk_der = pq_sk
            .to_der()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        let trad_sk_der = trad_sk
            .to_der()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(Self {
            pq_sk_der,
            trad_sk_der,
            oid: oid.to_string(),
        })
    }

    /// Create a new composite DSA private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA
    /// * `pq_sk` - The private key for the post-quantum DSA
    /// * `trad_sk` - The private key for the traditional DSA
    ///
    /// # Returns
    ///
    /// A new composite DSA private key
    pub fn new_dsa(oid: &str, pq_sk: &OctetString, trad_sk: &OctetString) -> Result<Self> {
        let pq_sk_der = pq_sk
            .to_der()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        let trad_sk_der = trad_sk
            .to_der()
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(Self {
            pq_sk_der,
            trad_sk_der,
            oid: oid.to_string(),
        })
    }

    /// Get the OID for the composite DSA / KEM
    ///
    /// # Returns
    ///
    /// The OID for the composite DSA / KEM
    pub fn get_oid(&self) -> &str {
        &self.oid
    }

    /// Get the private key for the post-quantum KEM
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum KEM
    pub fn get_kem_pq_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        let res = PrivateKeyInfo::from_der(self.pq_sk_der.as_slice())
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(res)
    }

    /// Get the private key for the post-quantum DSA
    ///
    /// # Returns
    ///
    /// The private key for the post-quantum DSA
    pub fn get_dsa_pq_sk(&self) -> Result<OctetString> {
        let res = OctetString::from_der(self.pq_sk_der.as_slice())
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(res)
    }

    /// Get the private key for the traditional KEM
    ///
    /// # Returns
    ///
    /// The private key for the traditional KEM
    pub fn get_kem_trad_sk(&self) -> Result<PrivateKeyInfo<'_>> {
        let res = PrivateKeyInfo::from_der(self.trad_sk_der.as_slice())
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(res)
    }

    /// Get the private key for the traditional DSA
    ///
    /// # Returns
    ///
    /// The private key for the traditional DSA
    pub fn get_dsa_trad_sk(&self) -> Result<OctetString> {
        let res = OctetString::from_der(self.trad_sk_der.as_slice())
            .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
        Ok(res)
    }

    /// Create a new composite private key from a DER-encoded private key
    ///
    /// # Arguments
    ///
    /// * `oid` - The OID for the composite DSA / KEM
    /// * `der` - The DER-encoded private key
    ///
    /// # Returns
    ///
    /// A new composite private key
    pub fn from_der(oid: &str, der: &[u8]) -> Result<Self> {
        // Check whether this is a DSA OID or a KEM OID
        if is_dsa_oid(oid) {
            let key_data = CompositeSignaturePrivateKey::from_der(der)
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            let comp = CompositePrivateKey::new_dsa(oid, &key_data.pq_sk, &key_data.trad_sk)
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            Ok(comp)
        } else {
            let key_data = CompositeKEMPrivateKey::from_der(der)
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            let comp = CompositePrivateKey::new_kem(oid, &key_data.pq_sk, &key_data.trad_sk)
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            Ok(comp)
        }
    }

    /// Encode the composite private key as a DER-encoded private key
    ///
    /// # Returns
    ///
    /// The DER-encoded private key
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Check whether this is a DSA OID or a KEM OID
        if is_dsa_oid(&self.oid) {
            let key_data = CompositeSignaturePrivateKey {
                pq_sk: OctetString::from_der(self.pq_sk_der.as_slice())
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?,
                trad_sk: OctetString::from_der(self.trad_sk_der.as_slice())
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?,
            };
            let res = key_data
                .to_der()
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            Ok(res)
        } else {
            let key_data = CompositeKEMPrivateKey {
                pq_sk: PrivateKeyInfo::from_der(self.pq_sk_der.as_slice())
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?,
                trad_sk: PrivateKeyInfo::from_der(self.trad_sk_der.as_slice())
                    .map_err(|_| QuantCryptError::InvalidPrivateKey)?,
            };
            let res = key_data
                .to_der()
                .map_err(|_| QuantCryptError::InvalidPrivateKey)?;
            Ok(res)
        }
    }
}
