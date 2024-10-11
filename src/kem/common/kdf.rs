use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512}; // should be kdfs not hashes
                                                  // Implement Copy and Debug for KemType
#[derive(Clone, Debug)]
/// The type of the Key Derivation Function (KDF)
// TODO: Align KEM with internet draft
// Ignore dead code for now
#[allow(dead_code)]
pub enum KdfType {
    HkdfSha256,
    Sha3_256,
    HkdfSha384,
    Sha3_512,
    Sha3_384,
}

/// The Key Derivation Function (KDF)
pub struct Kdf {
    kdf_type: KdfType,
}

impl Kdf {
    /// Create a new KDF
    ///
    /// # Arguments
    ///
    /// * `kdf_type` - The type of the KDF
    ///
    /// # Returns
    ///
    /// A new KDF
    pub fn new(kdf_type: KdfType) -> Self {
        Self { kdf_type }
    }

    /// Derive a key from the input
    ///
    /// # Arguments
    ///
    /// * `input` - The input to the KDF
    ///
    /// # Returns
    ///
    /// The derived key
    pub fn kdf(&self, input: &[u8]) -> Vec<u8> {
        match self.kdf_type {
            KdfType::HkdfSha256 => {
                let mut output = vec![0u8; 32];
                let hkdf = Hkdf::<Sha256>::new(None, input);
                hkdf.expand(&[0u8; 32], &mut output).unwrap();
                output
            }
            KdfType::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(input);
                hasher.finalize().to_vec()
            }
            KdfType::HkdfSha384 => {
                let mut output = vec![0u8; 48];
                let hkdf = Hkdf::<Sha384>::new(None, input);
                hkdf.expand(&[0u8; 48], &mut output).unwrap();
                output
            }
            KdfType::Sha3_384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(input);
                hasher.finalize().to_vec()
            }
            KdfType::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(input);
                hasher.finalize().to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let types = vec![
            KdfType::HkdfSha256,
            KdfType::Sha3_256,
            KdfType::HkdfSha384,
            KdfType::Sha3_512,
            KdfType::Sha3_384,
        ];
        for kdf_type in types {
            let kdf = Kdf::new(kdf_type.clone());
            let input = b"input";
            let output1 = kdf.kdf(input);
            assert_eq!(
                output1.len(),
                match kdf_type {
                    KdfType::HkdfSha256 => 32,
                    KdfType::Sha3_256 => 32,
                    KdfType::HkdfSha384 => 48,
                    KdfType::Sha3_512 => 64,
                    KdfType::Sha3_384 => 48,
                }
            );
            let output2 = kdf.kdf(input);
            assert_eq!(output1, output2);

            let output3 = kdf.kdf(b"input2");
            assert_ne!(output1, output3);
        }
    }
}
