use cms::enveloped_data::RecipientIdentifier;

use crate::certificates::Certificate;

/// Certificate store trait
pub trait CertificateStore {
    /// Find a certificate by recipient identifier.
    fn find(&self, ri: RecipientIdentifier) -> Option<Certificate>;
}
