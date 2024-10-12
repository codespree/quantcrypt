use crate::dsa::common::dsa_type::DsaType;

/// A trait to get the OID of a DSA
pub trait Oid {
    /// Get the OID for the DSA
    ///
    /// # Returns
    ///
    /// The OID for the DSA as a string
    fn get_oid(&self) -> String;
}

impl Oid for DsaType {
    /// Get the OID for the DSA
    ///
    /// # Returns
    ///
    /// The OID for the DSA
    fn get_oid(&self) -> String {
        match self {
            DsaType::Rsa2048PssSHA256 | DsaType::Rsa3072PssSHA512 => "1.2.840.113549.1.1.10",
            DsaType::Rsa2048Pkcs15SHA256 => "1.2.840.113549.1.1.11",
            DsaType::Rsa3072Pkcs15SHA512 => "1.2.840.113549.1.1.13",
            DsaType::EcdsaBrainpoolP256r1SHA256 | DsaType::EcdsaP256SHA256 => "1.2.840.10045.4.3.2",
            DsaType::EcdsaBrainpoolP256r1SHA512
            | DsaType::EcdsaBrainpoolP384r1SHA512
            | DsaType::EcdsaP256SHA512
            | DsaType::EcdsaP384SHA512 => "1.2.840.10045.4.3.4",
            DsaType::Ed25519SHA512 => "1.3.101.112",
            DsaType::Ed448SHA512 => "1.3.101.113",
            // TODO: https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oids.json
            // TODO: Remove support for IPD eventually
            #[cfg(not(feature = "ipd"))]
            DsaType::MlDsa44 => "2.16.840.1.101.3.4.3.17",
            #[cfg(not(feature = "ipd"))]
            DsaType::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            #[cfg(not(feature = "ipd"))]
            DsaType::MlDsa87 => "2.16.840.1.101.3.4.3.19",
            #[cfg(feature = "ipd")]
            DsaType::MlDsa44 => "1.3.6.1.4.1.2.267.12.4.4",
            #[cfg(feature = "ipd")]
            DsaType::MlDsa65 => "1.3.6.1.4.1.2.267.12.6.5",
            #[cfg(feature = "ipd")]
            DsaType::MlDsa87 => "1.3.6.1.4.1.2.267.12.8.7",

            // TODO: Change when finalized
            DsaType::MlDsa44Rsa2048PssSha256 => "2.16.840.1.114027.80.8.1.1",
            DsaType::MlDsa44Rsa2048Pkcs15Sha256 => "2.16.840.1.114027.80.8.1.2",
            DsaType::MlDsa44Ed25519SHA512 => "2.16.840.1.114027.80.8.1.3",
            DsaType::MlDsa44EcdsaP256SHA256 => "2.16.840.1.114027.80.8.1.4",
            DsaType::MlDsa44EcdsaBrainpoolP256r1SHA256 => "2.16.840.1.114027.80.8.1.5",
            DsaType::MlDsa65Rsa3072PssSHA512 => "2.16.840.1.114027.80.8.1.6",
            DsaType::MlDsa65Rsa3072Pkcs15SHA512 => "2.16.840.1.114027.80.8.1.7",
            DsaType::MlDsa65EcdsaP256SHA512 => "2.16.840.1.114027.80.8.1.8",
            DsaType::MlDsa65EcdsaBrainpoolP256r1SHA512 => "2.16.840.1.114027.80.8.1.9",
            DsaType::MlDsa65Ed25519SHA512 => "2.16.840.1.114027.80.8.1.10",
            DsaType::MlDsa87EcdsaP384SHA512 => "2.16.840.1.114027.80.8.1.11",
            DsaType::MlDsa87EcdsaBrainpoolP384r1SHA512 => "2.16.840.1.114027.80.8.1.12",
            DsaType::MlDsa87Ed448SHA512 => "2.16.840.1.114027.80.8.1.13",
        }
        .to_string()
    }
}
