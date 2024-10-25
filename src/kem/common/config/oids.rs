use crate::kem::common::kem_type::KemType;

/// A trait to get the OID of a KEM
pub trait Oid {
    /// Get the OID for the KEM
    ///
    /// # Returns
    ///
    /// The OID for the KEM as a string
    fn get_oid(&self) -> String;
}

impl Oid for KemType {
    /// Get the OID for the KEM
    ///
    /// # Returns
    ///
    /// The OID for the KEM
    fn get_oid(&self) -> String {
        match self {
            // Composite types from old version:
            KemType::MlKem512P256 => "2.16.840.1.114027.80.5.2.1",
            KemType::MlKem512BrainpoolP256r1 => "2.16.840.1.114027.80.5.2.2",
            KemType::MlKem512X25519 => "2.16.840.1.114027.80.5.2.3",
            KemType::MlKem512Rsa2048 => "2.16.840.1.114027.80.5.2.13",
            KemType::MlKem512Rsa3072 => "2.16.840.1.114027.80.5.2.4",
            KemType::MlKem768P256 => "2.16.840.1.114027.80.5.2.5",
            KemType::MlKem768BrainpoolP256r1 => "2.16.840.1.114027.80.5.2.6",
            KemType::MlKem768X25519 => "2.16.840.1.114027.80.5.2.7",
            KemType::MlKem1024P384 => "2.16.840.1.114027.80.5.2.8",
            KemType::MlKem1024BrainpoolP384r1 => "2.16.840.1.114027.80.5.2.9",
            KemType::MlKem1024X448 => "2.16.840.1.114027.80.5.2.10",

            // Composite types from editor's copy, skipped ones are also in old version:
            KemType::MlKem768Rsa2048 => "2.16.840.1.114027.80.5.2.21",
            KemType::MlKem768Rsa3072 => "2.16.840.1.114027.80.5.2.22",
            KemType::MlKem768Rsa4096 => "2.16.840.1.114027.80.5.2.23",
            // KemType::MlKem768X25519 => "2.16.840.1.114027.80.5.2.24",
            KemType::MlKem768P384 => "2.16.840.1.114027.80.5.2.25",
            // KemType::MlKem768BrainpoolP256r1 => "2.16.840.1.114027.80.5.2.26",
            // KemType::MlKem1024P384 => "2.16.840.1.114027.80.5.2.27",
            // KemType::MlKem1024BrainpoolP384r1 => "2.16.840.1.114027.80.5.2.28",
            // KemType::MlKem1024X448 => "2.16.840.1.114027.80.5.2.29",

            // EC Types:
            KemType::P256 => "1.2.840.10045.3.1.7",
            KemType::P384 => "1.3.132.0.34",
            KemType::X25519 => "1.3.101.110", // RFC 8410
            KemType::X448 => "1.3.101.111",
            KemType::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.7", // RFC 5639
            KemType::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.11",
            // RSA Types:
            KemType::RsaOAEP2048 => "1.2.840.113549.1.1.7",
            KemType::RsaOAEP3072 => "1.2.840.113549.1.1.7",
            KemType::RsaOAEP4096 => "1.2.840.113549.1.1.7",
            // ML Types:
            KemType::MlKem512 => "2.16.840.1.101.3.4.4.1",
            KemType::MlKem768 => "2.16.840.1.101.3.4.4.2",
            KemType::MlKem1024 => "2.16.840.1.101.3.4.4.3",

            // XWing:
            KemType::XWing => "1.3.6.1.4.1.62253.25722",
        }
        .to_string()
    }
}
