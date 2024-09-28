use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
}

#[derive(Error, Debug)]
pub enum KeyGenError {
    #[error("Key pair generation failed")]
    KeyPairGenerationFailed,
}
