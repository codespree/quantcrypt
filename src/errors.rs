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

#[derive(Error, Debug)]
pub enum CertificateBuilderError {
    #[error("Missing serial number")]
    MissingSerialNumber,
    #[error("Missing not_after")]
    MissingNotAfter,
    #[error("Missing subject")]
    MissingSubject,
    #[error("Missing public key")]
    MissingPublicKey,
    #[error("Bad private key")]
    BadPrivateKey,
    #[error("Bad public key")]
    BadPublicKey,
    #[error("Bad subject")]
    BadSubject,
    #[error("Bad issuers public key")]
    BadIssuersPublicKey,
    #[error("Bad serial number key")]
    BadSerialNumber,
    #[error("Invalid not before")]
    InvalidNotBefore,
    #[error("Invalid not after")]
    InvalidNotAfter,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unknown error")]
    Unknown,
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate is invalid")]
    InvalidCertificate,
}
