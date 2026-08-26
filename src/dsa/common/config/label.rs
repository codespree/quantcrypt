use crate::dsa::common::prehash_dsa_type::PrehashDsaType;

/// A trait to get the composite signature Label (domain separator) for a
/// Composite ML-DSA algorithm, as defined in
/// draft-ietf-lamps-pq-composite-sigs-19 Section 6 ("Signature Label Values").
///
/// The Label is a fixed per-algorithm ASCII string. It is used both as the
/// domain-separator component of the to-be-signed message
/// (`M' = Prefix || Label || len(ctx) || ctx || PH(M)`) and as the ML-DSA
/// context (`mldsa-ctx = Label`).
pub trait CompositeLabel {
    /// Get the composite signature Label bytes, or `None` if the algorithm is
    /// not a composite (pure ML-DSA / SLH-DSA have no Label).
    fn get_label(&self) -> Option<Vec<u8>>;
}

impl CompositeLabel for PrehashDsaType {
    fn get_label(&self) -> Option<Vec<u8>> {
        let label: &str = match self {
            PrehashDsaType::MlDsa44Rsa2048Pss => "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
            PrehashDsaType::MlDsa44Rsa2048Pkcs15 => "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
            PrehashDsaType::MlDsa44Ed25519 => "COMPSIG-MLDSA44-Ed25519-SHA512",
            PrehashDsaType::MlDsa44EcdsaP256 => "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
            PrehashDsaType::MlDsa65Rsa3072Pss => "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
            PrehashDsaType::MlDsa65Rsa3072Pkcs15 => "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
            PrehashDsaType::MlDsa65Rsa4096Pss => "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
            PrehashDsaType::MlDsa65Rsa4096Pkcs15 => "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
            PrehashDsaType::MlDsa65EcdsaP256 => "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
            PrehashDsaType::MlDsa65EcdsaP384 => "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
            PrehashDsaType::MlDsa65EcdsaBrainpoolP256r1 => "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
            PrehashDsaType::MlDsa65Ed25519 => "COMPSIG-MLDSA65-Ed25519-SHA512",
            PrehashDsaType::MlDsa87EcdsaP384 => "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
            PrehashDsaType::MlDsa87EcdsaBrainpoolP384r1 => "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
            PrehashDsaType::MlDsa87Ed448 => "COMPSIG-MLDSA87-Ed448-SHAKE256",
            PrehashDsaType::MlDsa87Rsa3072Pss => "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
            PrehashDsaType::MlDsa87Rsa4096Pss => "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
            PrehashDsaType::MlDsa87EcdsaP521 => "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
            // Pure ML-DSA, HashML-DSA, and SLH-DSA are not composites.
            _ => return None,
        };
        Some(label.as_bytes().to_vec())
    }
}
