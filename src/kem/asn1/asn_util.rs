use der::{oid::ObjectIdentifier, Encode};

use std::error;
// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub fn oid_to_der(oid: &str) -> Result<Vec<u8>> {
    Ok(ObjectIdentifier::new_unwrap(oid).to_der()?.to_vec())
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
        ];

        for (oid, hex_string) in oid_tests {
            let der = oid_to_der(oid).unwrap();
            let expected_der = hex::decode(hex_string).unwrap();
            assert_eq!(expected_der, der);
        }
    }
}
