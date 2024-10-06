use cms::enveloped_data::RecipientIdentifier;

use crate::Certificate;

/// Certificate store trait
pub trait CertificateStore {
    fn find(&self, ri: RecipientIdentifier) -> Option<Certificate>;
}
