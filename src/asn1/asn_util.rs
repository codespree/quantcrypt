use der::{oid::ObjectIdentifier, Encode};

use crate::{
    dsa::common::{dsa_type::DsaType, prehash_dsa_type::PrehashDsaType},
    dsas::DsaAlgorithm,
    errors,
    kem::common::kem_type::KemType,
    kems::KemAlgorithm,
};

// Change the alias to use `QuantCryptError`.
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
        // This tests the Domain separator encoding:
        //https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html#name-algorithm-identifiers

        let oid_tests = vec![
            ("2.16.840.1.114027.80.5.2.21", "060B6086480186FA6B50050215"),
            ("2.16.840.1.114027.80.5.2.22", "060B6086480186FA6B50050216"),
            ("2.16.840.1.114027.80.5.2.23", "060B6086480186FA6B50050217"),
            ("2.16.840.1.114027.80.5.2.24", "060B6086480186FA6B50050218"),
            ("2.16.840.1.114027.80.5.2.25", "060B6086480186FA6B50050219"),
            ("2.16.840.1.114027.80.5.2.26", "060B6086480186FA6B5005021A"),
            ("2.16.840.1.114027.80.5.2.27", "060B6086480186FA6B5005021B"),
            ("2.16.840.1.114027.80.5.2.28", "060B6086480186FA6B5005021C"),
            ("2.16.840.1.114027.80.5.2.29", "060B6086480186FA6B5005021D"),
            ("2.16.840.1.114027.80.8.1.1", "060B6086480186FA6B50080101"),
        ];

        for (oid, hex_string) in oid_tests {
            let der = oid_to_der(oid).unwrap();
            let expected_der = hex::decode(hex_string).unwrap();
            assert_eq!(expected_der, der);
        }
    }
}
