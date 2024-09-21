use crate::kem::common::kem_type::KemType;

pub trait Oid {
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
            // Composite types:
            KemType::MlKem768Rsa2048 => "2.16.840.1.114027.80.5.2.21",
            KemType::MlKem768Rsa3072 => "2.16.840.1.114027.80.5.2.22",
            KemType::MlKem768Rsa4096 => "2.16.840.1.114027.80.5.2.23",
            KemType::MlKem768X25519 => "2.16.840.1.114027.80.5.2.24",
            KemType::MlKem768P384 => "2.16.840.1.114027.80.5.2.25",
            KemType::MlKem768BrainpoolP256r1 => "2.16.840.1.114027.80.5.2.26",
            KemType::MlKem1024P384 => "2.16.840.1.114027.80.5.2.27",
            KemType::MlKem1024BrainpoolP384r1 => "2.16.840.1.114027.80.5.2.28",
            KemType::MlKem1024X448 => "2.16.840.1.114027.80.5.2.29",
            // EC Types:
            KemType::P256 => "1.2.840.10045.3.1.7",
            KemType::P384 => "1.3.132.0.34",
            KemType::X25519 => "1.3.101.110", // RFC 8410
            KemType::X448 => "1.3.101.110",
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
        }
        .to_string()
    }
}
