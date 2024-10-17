/// Utility class to compute composite overhead for ct, pk and sk
/// TODO: Add in compute logic for sk after pk is removed from private key info
#[allow(dead_code)]
pub fn compute_length_overhead(length: usize) -> usize {
    if length < 128 {
        return 1; // Short form encoding requires 1 byte
    } else {
        // Long form encoding
        let mut num_length_bytes = 0;
        let mut temp_length = length;

        // Calculate the number of bytes needed for the length
        while temp_length > 0 {
            num_length_bytes += 1;
            temp_length >>= 8; // Shift right by 8 bits
        }

        // First byte (for long form) + number of length bytes
        return 1 + num_length_bytes; // 1 for the first byte + bytes for the length
    }
}

#[allow(dead_code)]
pub fn compute_octet_overhead(octet_str_len: usize) -> usize {
    let tag_overhead = 1;
    let length_overhead = compute_length_overhead(octet_str_len);
    tag_overhead + length_overhead
}

#[allow(dead_code)]
pub fn compute_bit_overhead(bit_str_len: usize) -> usize {
    let tag_overhead = 1;
    let unused_bit_overhead = 1;
    let length_overhead = compute_length_overhead(bit_str_len);
    tag_overhead + length_overhead + unused_bit_overhead
}

#[allow(dead_code)]
pub fn compute_seq_overhead(sequence_len: usize) -> usize {
    let tag_overhead = 1;
    let length_overhead = compute_length_overhead(sequence_len);
    tag_overhead + length_overhead
}

#[allow(dead_code)]
pub fn compute_composite_ct_overhead(pq_ct_len: usize, trad_ct_len: usize) -> usize {
    /*
    ASN.1 Representation of Ciphertext (ct)

    Ciphertext ::= SEQUENCE {
        pq_ct   OCTET STRING,  
        trad_ct OCTET STRING,
    }
    */
    let pq_oct_overhead = compute_octet_overhead(pq_ct_len);
    let trad_oct_overhead = compute_octet_overhead(trad_ct_len);
    let seq_overhead = compute_seq_overhead(pq_ct_len + trad_ct_len + pq_oct_overhead + trad_oct_overhead);

    pq_oct_overhead + trad_oct_overhead + seq_overhead
}

#[allow(dead_code)]
pub fn compute_composite_pk_overhead(pq_pk_len: usize, trad_pk_len: usize) -> usize {
    /*
    ASN.1 Representation of Public Key (pk)

    PublicKey ::= SEQUENCE {
        pq_pk   BIT STRING,  
        trad_pk BIT STRING,
    }
    */
    let pq_pk_overhead = compute_bit_overhead(pq_pk_len);
    let trad_pk_overhead = compute_bit_overhead(trad_pk_len);
    let seq_overhead = compute_seq_overhead(pq_pk_len + trad_pk_len + pq_pk_overhead + trad_pk_overhead);

    pq_pk_overhead + trad_pk_overhead + seq_overhead
}

// Test cases
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512p256_ct() {
        let expected_overhead = 10;
        let actual_overhead = compute_composite_ct_overhead(768, 65);
        assert_eq!(expected_overhead, actual_overhead, "Test for MlKem512P256 ct overhead computation failed. Expected: {}, Actual: {}", expected_overhead, actual_overhead);
    }

    #[test]
    fn test_mlkem512rsa2048_ct() {
        let expected_overhead = 12;
        let actual_overhead = compute_composite_ct_overhead(768, 256);
        assert_eq!(expected_overhead, actual_overhead, "Test for MlKem512Rsa2048 ct overhead computation failed. Expected: {}, Actual: {}", expected_overhead, actual_overhead);
    }

    #[test]
    fn test_mlkem512p256_pk() {
        let expected_overhead = 12;
        let actual_overhead = compute_composite_pk_overhead(800, 65);
        assert_eq!(expected_overhead, actual_overhead, "Test for MlKem512P256 pk overhead computation failed. Expected: {}, Actual: {}", expected_overhead, actual_overhead);
    }

    #[test]
    fn test_mlkem512rsa2048_pk() {
        let expected_overhead = 14;
        let actual_overhead = compute_composite_pk_overhead(800, 270);
        assert_eq!(expected_overhead, actual_overhead, "Test for MlKem512Rsa2048 pk overhead computation failed. Expected: {}, Actual: {}", expected_overhead, actual_overhead);
    }
}
