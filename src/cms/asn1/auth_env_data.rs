//! `AuthEnvelopedData`-related types

// Thanks to Carl Wallace for this code:
// https://github.com/carl-wallace/kemri_toy/blob/main/src/asn1/auth_env_data.rs

use cms::{
    authenticated_data::MessageAuthenticationCode,
    content_info::CmsVersion,
    enveloped_data::{EncryptedContentInfo, OriginatorInfo, RecipientInfos},
};
use der::Sequence;
use x509_cert::attr::Attributes;

/// The `AuthEnvelopedData` type is defined in [RFC 5083 Section 2.1].
///
/// ```text
///      AuthEnvelopedData ::= SEQUENCE {
///         version CMSVersion,
///         originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///         recipientInfos RecipientInfos,
///         authEncryptedContentInfo EncryptedContentInfo,
///         authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
///         mac MessageAuthenticationCode,
///         unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
///
/// [RFC 5083 Section 2.1]: https://www.rfc-editor.org/rfc/rfc5083#section-2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AuthEnvelopedData {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo>,
    pub recip_infos: RecipientInfos,
    pub auth_encrypted_content: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub auth_attrs: Option<Attributes>,
    pub mac: MessageAuthenticationCode,
    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unauth_attrs: Option<Attributes>,
}
