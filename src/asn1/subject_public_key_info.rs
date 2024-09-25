// This code is adapted from picky-asn1-x509 crate.
// It is less picky which suits the needs of this project better.
// It may be a conscoius decision to have this crate only deal with composite
// keys and certificates and not with the full X.509 standard.
// Those checks will be added in the future.

use std::fmt;

use picky_asn1::wrapper::BitStringAsn1;

use crate::asn1::algorithm_identifier::AlgorithmIdentifier;
use crate::asn1::macros::seq_next_element;
use serde::{de, ser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitStringAsn1,
}

impl SubjectPublicKeyInfo {}

impl ser::Serialize for SubjectPublicKeyInfo {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        use ser::SerializeSeq;

        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.algorithm)?;
        seq.serialize_element(&self.subject_public_key)?;

        seq.end()
    }
}

impl<'de> de::Deserialize<'de> for SubjectPublicKeyInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SubjectPublicKeyInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded subject public key info")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let algorithm: AlgorithmIdentifier =
                    seq_next_element!(seq, AlgorithmIdentifier, "algorithm oid");
                let subject_public_key =
                    seq_next_element!(seq, BitStringAsn1, "subject public key");

                Ok(SubjectPublicKeyInfo {
                    algorithm,
                    subject_public_key,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}
