use cms::enveloped_data::RecipientIdentifier;

use crate::Certificate;

/// Key Encapsulation Mechanism (KEM) trait
pub trait CertificateStore {
    fn find(&self, ri: RecipientIdentifier) -> Option<Certificate>;
}
