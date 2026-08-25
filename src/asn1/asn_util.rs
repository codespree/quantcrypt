use der::{oid::ObjectIdentifier, Encode};

use crate::{
    dsa::common::{dsa_type::DsaType, prehash_dsa_type::PrehashDsaType},
    dsas::DsaAlgorithm,
    errors,
    kem::common::kem_type::KemType,
    kems::KemAlgorithm,
};

// Change the alias to use `QuantCryptError`.
#[allow(dead_code)]
type Result<T> = std::result::Result<T, errors::QuantCryptError>;

/// Convert an OID string to a DER encoded byte array
/// represeting an ASN.1 Object Identifier
///
/// # Arguments
///
/// * `oid` - The OID string to convert
///
/// # Returns
///
/// The DER encoded byte array
///
/// # Errors
///
/// `QuantCryptError::InvalidOid` will be returned if the OID is invalid
///
/// Retained as a general-purpose utility (and exercised by the unit test
/// below); the composite constructions now use fixed per-algorithm Labels
/// rather than DER-encoded OIDs as domain separators.
#[allow(dead_code)]
pub fn oid_to_der(oid: &str) -> Result<Vec<u8>> {
    let oid = ObjectIdentifier::new_unwrap(oid)
        .to_der()
        .map_err(|_| errors::QuantCryptError::InvalidOid)?;
    Ok(oid.to_vec())
}

/// Check if an OID is a valid KEM / DSA OID
///
/// # Arguments
///
/// * `oid` - The OID to check
///
/// # Returns
///
/// True if the OID is valid, false otherwise
pub fn is_valid_kem_or_dsa_oid(oid: &String) -> bool {
    // Get all oids based on dsa and kem types as a string array
    let dsa_oids = DsaAlgorithm::all();
    let kem_oids = KemAlgorithm::all();

    let all_dsa_oids: Vec<String> = dsa_oids.iter().map(|x| x.get_oid()).collect();
    let all_kem_oids: Vec<String> = kem_oids.iter().map(|x| x.get_oid()).collect();

    // Check if oid is valid
    all_dsa_oids.contains(oid) || all_kem_oids.contains(oid)
}

/// Check if an OID is a composite KEM / DSA OID
///
/// # Arguments
///
/// * `oid` - The OID to check
///
/// # Returns
///
/// True if the OID is a composite OID, false otherwise
pub fn is_composite_kem_or_dsa_oid(oid: &str) -> bool {
    let is_composite_kem = if let Some(k_type) = KemType::from_oid(oid) {
        k_type.is_composite()
    } else {
        false
    };

    let is_composite_dsa = if let Some(d_type) = DsaType::from_oid(oid) {
        d_type.is_composite()
    } else {
        false
    };

    let is_composite_prehash_dsa = if let Some(d_type) = PrehashDsaType::from_oid(oid) {
        d_type.is_composite()
    } else {
        false
    };

    is_composite_kem || is_composite_dsa || is_composite_prehash_dsa
}

/// Check if an OID is a KEM OID
///
/// # Arguments
///
/// * `oid` - The OID to check
///
/// # Returns
///
/// True if the OID is a KEM OID, false otherwise
pub fn is_kem_oid(oid: &str) -> bool {
    KemAlgorithm::from_oid(oid).is_some()
}

/// Check if an OID is a DSA OID
///
/// # Arguments
///
/// * `oid` - The OID to check
///
/// # Returns
///
/// True if the OID is a DSA OID, false otherwise
pub fn is_dsa_oid(oid: &str) -> bool {
    DsaAlgorithm::from_oid(oid).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_to_der() {
        use der::Decode;

        // Round-trip a representative set of production composite OIDs
        // (draft-ietf-lamps-pq-composite-sigs-19 / -kem-15).
        let oids = vec![
            "1.3.6.1.5.5.7.6.37", // MLDSA44-RSA2048-PSS-SHA256
            "1.3.6.1.5.5.7.6.54", // MLDSA87-ECDSA-P521-SHA512
            "1.3.6.1.5.5.7.6.55", // MLKEM768-RSA2048
            "1.3.6.1.5.5.7.6.66", // MLKEM1024-ECDH-P521
        ];

        for oid in oids {
            let der = oid_to_der(oid).unwrap();
            let decoded = ObjectIdentifier::from_der(&der).unwrap();
            assert_eq!(decoded.to_string(), oid);
        }
    }
}
