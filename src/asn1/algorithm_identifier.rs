// This code is adapted from picky-asn1-x509 crate.
// It is less picky which suits the needs of this project better.
// It may be a conscoius decision to have this crate only deal with composite
// keys and certificates and not with the full X.509 standard.
// Those checks will be added in the future.

use std::fmt;

use crate::asn1::macros::seq_next_element;
use picky_asn1::wrapper::ObjectIdentifierAsn1;
use serde::{de, ser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AlgorithmIdentifierParameters {
    None,
    Null,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlgorithmIdentifier {
    algorithm: ObjectIdentifierAsn1,
    parameters: AlgorithmIdentifierParameters,
}

impl AlgorithmIdentifier {
    pub fn new(algorithm: ObjectIdentifierAsn1, parameters: AlgorithmIdentifierParameters) -> Self {
        Self {
            algorithm,
            parameters,
        }
    }

    pub fn algorithm(&self) -> &ObjectIdentifierAsn1 {
        &self.algorithm
    }

    pub fn parameters(&self) -> &AlgorithmIdentifierParameters {
        &self.parameters
    }
}

impl<'de> de::Deserialize<'de> for AlgorithmIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = AlgorithmIdentifier;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded algorithm identifier")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 =
                    seq_next_element!(seq, AlgorithmIdentifier, "algorithm oid");

                // TODO: Diable clippy warning for now and later add OID check for composite algorithms
                #[allow(clippy::match_single_binding)]
                let args = match Into::<String>::into(&oid.0).as_str() {
                    // TODO: We can filter by OIDs here and raise an error if the parameters are not as expected.
                    _ => {
                        // Try to deserialize next element in sequence.
                        // Error is ignored because some implementations just leave no parameter at all for
                        // RSA encryption (ie: rsa-export-0.1.1 crate) but we still want to be able
                        // to parse their output.
                        let _ = seq.next_element::<()>();
                        AlgorithmIdentifierParameters::None
                    }
                };

                Ok(AlgorithmIdentifier {
                    algorithm: oid,
                    parameters: args,
                })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

impl ser::Serialize for AlgorithmIdentifier {
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
        match &self.parameters {
            AlgorithmIdentifierParameters::None => {}
            AlgorithmIdentifierParameters::Null => {
                seq.serialize_element(&())?;
            }
        }
        seq.end()
    }
}
