// This code is adapted from picky-asn1-x509 crate.
// It is less picky which suits the needs of this project better.
// It may be a conscoius decision to have this crate only deal with composite
// keys and certificates and not with the full X.509 standard.
// Those checks will be added in the future.

use crate::asn1::algorithm_identifier::AlgorithmIdentifier;
use crate::asn1::macros::serde_invalid_value;
use crate::asn1::subject_public_key_info::SubjectPublicKeyInfo;
use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag3, IntegerAsn1};
use picky_asn1_x509::{Extensions, Name, Validity, Version};
use serde::{de, Serialize};
use std::fmt;

/// [RFC 5280 #4.1](https://tools.ietf.org/html/rfc5280#section-4.1)
///
/// ```not_rust
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  EXPLICIT Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      extensions      [3]  EXPLICIT Extensions OPTIONAL
///                           -- If present, version MUST be v3
///      }
/// ```
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TbsCertificate {
    #[serde(skip_serializing_if = "version_is_default")]
    pub version: ExplicitContextTag0<Version>,
    pub serial_number: IntegerAsn1,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    // issuer_unique_id
    // subject_unique_id
    #[serde(skip_serializing_if = "extensions_are_empty")]
    pub extensions: ExplicitContextTag3<Extensions>,
}

fn version_is_default(version: &Version) -> bool {
    version == &Version::default()
}

// Implement Deserialize manually to support missing version field (i.e.: fallback as V1)
impl<'de> de::Deserialize<'de> for TbsCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = TbsCertificate;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TBSCertificate")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let version: ExplicitContextTag0<Version> =
                    seq.next_element().unwrap_or_default().unwrap_or_default();
                let serial_number = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let signature = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let issuer = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let validity = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let subject = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;
                let subject_public_key_info = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(6, &self))?;
                let extensions: ExplicitContextTag3<Extensions> = seq
                    .next_element()?
                    .unwrap_or_else(|| Some(Extensions(Vec::new()).into()))
                    .unwrap_or_else(|| Extensions(Vec::new()).into());

                if version.0 != Version::V3 && !(extensions.0).0.is_empty() {
                    return Err(serde_invalid_value!(
                        TbsCertificate,
                        "Version is not V3, but Extensions are present",
                        "no Extensions"
                    ));
                }

                Ok(TbsCertificate {
                    version,
                    serial_number,
                    signature,
                    issuer,
                    validity,
                    subject,
                    subject_public_key_info,
                    extensions,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

fn extensions_are_empty(extensions: &Extensions) -> bool {
    extensions.0.is_empty()
}
