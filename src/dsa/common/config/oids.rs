use crate::dsa::common::dsa_type::DsaType;
use crate::dsa::common::prehash_dsa_type::PrehashDsaType;

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
            // rsassa-pss(10)
            // [other identifier: id-RSASSA-PSS]
            DsaType::Rsa2048PssSha256 | DsaType::Rsa3072PssSha256 | DsaType::Rsa4096PssSha384 => {
                "1.2.840.113549.1.1.10"
            }
            // sha256WithRSAEncryption(11)
            DsaType::Rsa2048Pkcs15Sha256 | DsaType::Rsa3072Pkcs15Sha256 => "1.2.840.113549.1.1.11",
            // sha384WithRSAEncryption(12)
            DsaType::Rsa4096Pkcs15Sha384 => "1.2.840.113549.1.1.12",
            // ECDSA with SHA256
            DsaType::EcdsaBrainpoolP256r1SHA256 | DsaType::EcdsaP256SHA256 => "1.2.840.10045.4.3.2",
            // ECDSA with SHA384
            DsaType::EcdsaP384SHA384 | DsaType::EcdsaBrainpoolP384r1SHA384 => "1.2.840.10045.4.3.3",
            // ECDSA with SHA512
            DsaType::EcdsaP521SHA512 => "1.2.840.10045.4.3.4",
            DsaType::Ed25519 => "1.3.101.112",
            DsaType::Ed448 => "1.3.101.113",
        }
        .to_string()
    }
}

impl Oid for PrehashDsaType {
    /// Get the OID for the prehash DSA
    ///
    /// # Returns
    ///
    /// The OID for the prehash DSA
    fn get_oid(&self) -> String {
        match self {
            // TODO: https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oids.json
            PrehashDsaType::MlDsa44 => "2.16.840.1.101.3.4.3.17",
            PrehashDsaType::MlDsa65 => "2.16.840.1.101.3.4.3.18",
            PrehashDsaType::MlDsa87 => "2.16.840.1.101.3.4.3.19",

            PrehashDsaType::HashMlDsa44 => "2.16.840.1.101.3.4.3.32",
            PrehashDsaType::HashMlDsa65 => "2.16.840.1.101.3.4.3.33",
            PrehashDsaType::HashMlDsa87 => "2.16.840.1.101.3.4.3.34",

            // Composite ML-DSA Signature Algorithms
            // (draft-ietf-lamps-pq-composite-sigs-19, production IANA arc).
            PrehashDsaType::MlDsa44Rsa2048Pss => "1.3.6.1.5.5.7.6.37",
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => "1.3.6.1.5.5.7.6.38",
            PrehashDsaType::MlDsa44Ed25519 => "1.3.6.1.5.5.7.6.39",
            PrehashDsaType::MlDsa44EcdsaP256 => "1.3.6.1.5.5.7.6.40",
            PrehashDsaType::MlDsa65Rsa3072Pss => "1.3.6.1.5.5.7.6.41",
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => "1.3.6.1.5.5.7.6.42",
            PrehashDsaType::MlDsa65Rsa4096Pss => "1.3.6.1.5.5.7.6.43",
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => "1.3.6.1.5.5.7.6.44",
            PrehashDsaType::MlDsa65EcdsaP256 => "1.3.6.1.5.5.7.6.45",
            PrehashDsaType::MlDsa65EcdsaP384 => "1.3.6.1.5.5.7.6.46",
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => "1.3.6.1.5.5.7.6.47",
            PrehashDsaType::MlDsa65Ed25519 => "1.3.6.1.5.5.7.6.48",
            PrehashDsaType::MlDsa87EcdsaP384 => "1.3.6.1.5.5.7.6.49",
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => "1.3.6.1.5.5.7.6.50",
            PrehashDsaType::MlDsa87Ed448 => "1.3.6.1.5.5.7.6.51",
            PrehashDsaType::MlDsa87Rsa3072Pss => "1.3.6.1.5.5.7.6.52",
            PrehashDsaType::MlDsa87Rsa4096Pss => "1.3.6.1.5.5.7.6.53",
            PrehashDsaType::MlDsa87EcdsaP521 => "1.3.6.1.5.5.7.6.54",

            PrehashDsaType::SlhDsaSha2_128s => "2.16.840.1.101.3.4.3.20",
            PrehashDsaType::SlhDsaSha2_128f => "2.16.840.1.101.3.4.3.21",
            PrehashDsaType::SlhDsaSha2_192s => "2.16.840.1.101.3.4.3.22",
            PrehashDsaType::SlhDsaSha2_192f => "2.16.840.1.101.3.4.3.23",
            PrehashDsaType::SlhDsaSha2_256s => "2.16.840.1.101.3.4.3.24",
            PrehashDsaType::SlhDsaSha2_256f => "2.16.840.1.101.3.4.3.25",
            PrehashDsaType::SlhDsaShake128s => "2.16.840.1.101.3.4.3.26",
            PrehashDsaType::SlhDsaShake128f => "2.16.840.1.101.3.4.3.27",
            PrehashDsaType::SlhDsaShake192s => "2.16.840.1.101.3.4.3.28",
            PrehashDsaType::SlhDsaShake192f => "2.16.840.1.101.3.4.3.29",
            PrehashDsaType::SlhDsaShake256s => "2.16.840.1.101.3.4.3.30",
            PrehashDsaType::SlhDsaShake256f => "2.16.840.1.101.3.4.3.31",

            // Prehash SLH-DSA
            PrehashDsaType::HashSlhDsaSha2_128s => "2.16.840.1.101.3.4.3.35",
            PrehashDsaType::HashSlhDsaSha2_128f => "2.16.840.1.101.3.4.3.36",
            PrehashDsaType::HashSlhDsaSha2_192s => "2.16.840.1.101.3.4.3.37",
            PrehashDsaType::HashSlhDsaSha2_192f => "2.16.840.1.101.3.4.3.38",
            PrehashDsaType::HashSlhDsaSha2_256s => "2.16.840.1.101.3.4.3.39",
            PrehashDsaType::HashSlhDsaSha2_256f => "2.16.840.1.101.3.4.3.40",
            PrehashDsaType::HashSlhDsaShake128s => "2.16.840.1.101.3.4.3.41",
            PrehashDsaType::HashSlhDsaShake128f => "2.16.840.1.101.3.4.3.42",
            PrehashDsaType::HashSlhDsaShake192s => "2.16.840.1.101.3.4.3.43",
            PrehashDsaType::HashSlhDsaShake192f => "2.16.840.1.101.3.4.3.44",
            PrehashDsaType::HashSlhDsaShake256s => "2.16.840.1.101.3.4.3.45",
            PrehashDsaType::HashSlhDsaShake256f => "2.16.840.1.101.3.4.3.46",
        }
        .to_string()
    }
}
