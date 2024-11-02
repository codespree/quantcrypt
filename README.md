# QuantCrypt

![Crates.io Version](https://img.shields.io/crates/v/quantcrypt)
 ![example workflow](https://github.com/codespree/quantcrypt/actions/workflows/rust.yml/badge.svg) [![dependency status](https://deps.rs/repo/github/codespree/quantcrypt/status.svg)](https://deps.rs/repo/github/codespree/quantcrypt) 

The goal of this library is to provide a simple and easy-to-use 
interface for generating key pairs, certificates, signing and verifying messages, and encrypting and decrypting messages using post-quantum cryptographic algorithms.

A secondary goal is to provide a set of cryptographic algorithms that are compatible with existing X.509, PKIX, and CMS data structures and protocols and to support the efforts of the [LAMPS Working Group](https://datatracker.ietf.org/wg/lamps/about/) in the IETF especially the [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) and [draft-ietf-lamps-pq-composite-kem](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/) drafts.

## Including quantcrypt in your project

Import quantcrypt into your project by adding the following lines to your Cargo.toml.
```toml
[dependencies]
quantcrypt = "0.2.0"
```

## Generating PQC Hackathon Artifacts for [IETF Hackathon - PQC Certificates](https://github.com/IETF-Hackathon/pqc-certificates)

```ignore
cargo test gen_pq_hackathon_artifacts_r4 --release # generate artifacts in r4 format
```

To generate submissios zips:
```ignore
python prepare_submission.py # Select appropriate certificates and archive them as zips for submission
```

Artifacts in both [r3](https://github.com/IETF-Hackathon/pqc-certificates?tab=readme-ov-file#zip-format-r3---deprecated-will-be-removed-at-hackathon-in-november-2024) and [r4](https://github.com/IETF-Hackathon/pqc-certificates?tab=readme-ov-file#zip-format-r4) format are generated. They can be found in `artifacts/submission` folder.

## Interoperability Results

Once the artifacts are submitted to the IETF Hackathon PQC Certificates repository, the interoperability results can be found at the [IETF PQC Hackathon Certificate Automated Verification Interoperability Results](https://ietf-hackathon.github.io/pqc-certificates/pqc_hackathon_results_certs_r4.html) page.

## Generating Key Pairs and Certificates

The following snippet demonstrates how to generate a key pair and a certificate using the DSA and KEM algorithms. In addition to pure ML-DSA and ML-KEM algorithms, the library also supports composite algorithms that combine a traditional and post-quantum algorithm into a single key pair and certificate.

```rust
use quantcrypt::certificates::CertificateBuilder;
use quantcrypt::dsas::DsaAlgorithm;
use quantcrypt::kems::KemAlgorithm;
use quantcrypt::certificates::Profile;
use quantcrypt::dsas::DsaKeyGenerator;
use quantcrypt::kems::KemKeyGenerator;
use quantcrypt::certificates::CertValidity;

// Create a TA key pair
let (pk_root, sk_root) = DsaKeyGenerator::new(DsaAlgorithm::MlDsa44).generate().unwrap();

let profile = Profile::Root;
let serial_no = None; // This will generate a random serial number
let validity = CertValidity::new(None, "2035-01-01T00:00:00Z").unwrap(); // Not before is now
let subject = "CN=example.com".to_string();
let cert_public_key = pk_root.clone();
let signer = &sk_root;

// Create the TA certificate builder
let builder = CertificateBuilder::new(
    profile,
    serial_no,
    validity.clone(),
    subject.clone(),
    cert_public_key,
    signer
).unwrap();
let cert_root = builder.build().unwrap();
assert!(cert_root.verify_self_signed().unwrap());

// Create a leaf (EE) key pair for KEM
let (pk_kem, sk_kem) = KemKeyGenerator::new(KemAlgorithm::MlKem512).generate().unwrap();
let builder = CertificateBuilder::new(
    Profile::Leaf {
        issuer: cert_root.get_subject(),
        enable_key_agreement: false,
        enable_key_encipherment: true,
    },
    serial_no,
    validity,
    subject,
    pk_kem,
    signer
).unwrap();
let cert_kem = builder.build().unwrap();

// It's not self signed so verification so self signed should fail
assert!(!cert_kem.verify_self_signed().unwrap());

// But it should verify against the root
assert!(cert_root.verify_child(&cert_kem).unwrap());
```

## Generating Enveloped Data CMS Message

The following snippet demonstrates how to generate a CMS message using the DSA and KEM algorithms.

```rust
use quantcrypt::content::EnvelopedDataContent;
use quantcrypt::content::ContentEncryptionAlgorithm;
use quantcrypt::certificates::Certificate;
use quantcrypt::keys::PrivateKey;
use quantcrypt::kdfs::KdfType;
use quantcrypt::wraps::WrapType;
use quantcrypt::content::UserKeyingMaterial;
use quantcrypt::content::ObjectIdentifier;
use quantcrypt::content::Attribute;
use quantcrypt::content::Tag;
use quantcrypt::content::AttributeValue;
use quantcrypt::content::SetOfVec;

// Based on whether IPD feature is enabled or not, use the appropriate test data
let rc_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der";

let recipient_cert = Certificate::from_file(
    rc_filename,
).unwrap();

let sk_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der";

let private_key = PrivateKey::from_file(
    sk_filename
).unwrap();

let ukm = UserKeyingMaterial::new("test".as_bytes()).unwrap();
let data = b"abc";

let attribute_oid = ObjectIdentifier::new("1.3.6.1.4.1.22554.5.6").unwrap();
let mut attribute_vals: SetOfVec<AttributeValue> = SetOfVec::<AttributeValue>::new();

let attr_val = AttributeValue::new(Tag::OctetString, data.to_vec()).unwrap();
attribute_vals.insert(attr_val).unwrap();

let attribute = Attribute {
    oid: attribute_oid,
    values: attribute_vals,
};

let mut builder = EnvelopedDataContent::get_builder(ContentEncryptionAlgorithm::Aes128Cbc).unwrap();

builder
    .kem_recipient(
        &recipient_cert,
        &KdfType::HkdfWithSha256,
        &WrapType::Aes256,
        Some(ukm),
    )
    .unwrap()
    .content(data)
    .unwrap()
    .unprotected_attribute(&attribute)
    .unwrap();

let content = builder.build().unwrap();

// Now use this content to create a new EnvelopedDataContent
let edc = EnvelopedDataContent::from_bytes_for_kem_recipient(
    &content,
    &recipient_cert,
    &private_key,
).unwrap();
assert_eq!(edc.get_content(), data);
```

## Generating Auth Enveloped Data CMS Message

Auth Enveloped Data is much like the above snippet but using `AuthEnvelopedDataContent` instead of `EnvelopedDataContent`.

```rust
use quantcrypt::content::AuthEnvelopedDataContent;
use quantcrypt::content::ContentEncryptionAlgorithmAead;
use quantcrypt::certificates::Certificate;
use quantcrypt::keys::PrivateKey;
use quantcrypt::kdfs::KdfType;
use quantcrypt::wraps::WrapType;
use quantcrypt::content::UserKeyingMaterial;
use quantcrypt::content::ObjectIdentifier;
use quantcrypt::content::Attribute;
use quantcrypt::content::Tag;
use quantcrypt::content::AttributeValue;
use quantcrypt::content::SetOfVec;

let rc_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_ee.der";

let recipient_cert = Certificate::from_file(
    rc_filename,
).unwrap();

let sk_filename = "test/data/cms/2.16.840.1.101.3.4.4.1_MlKem512_priv.der";

let private_key = PrivateKey::from_file(
    sk_filename
).unwrap();

let ukm = UserKeyingMaterial::new("test".as_bytes()).unwrap();
let data = b"abc";

let attribute_oid = ObjectIdentifier::new("1.3.6.1.4.1.22554.5.6").unwrap();
let mut attribute_vals: SetOfVec<AttributeValue> = SetOfVec::<AttributeValue>::new();

let attr_val = AttributeValue::new(Tag::OctetString, data.to_vec()).unwrap();
attribute_vals.insert(attr_val).unwrap();

let attribute = Attribute {
    oid: attribute_oid,
    values: attribute_vals,
};

let mut builder = AuthEnvelopedDataContent::get_builder(ContentEncryptionAlgorithmAead::Aes256Gcm).unwrap();

builder
    .kem_recipient(
        &recipient_cert,
        &KdfType::HkdfWithSha256,
        &WrapType::Aes256,
        Some(ukm),
    )
    .unwrap()
    .content(data)
    .unwrap()
    .auth_attribute(&attribute)
    .unwrap();

let content = builder.build().unwrap();

// Now use this content to create a new AuthEnvelopedDataContent
let edc = AuthEnvelopedDataContent::from_bytes_for_kem_recipient(
    &content,
    &recipient_cert,
    &private_key,
).unwrap();
assert_eq!(edc.get_content(), data);
```

## Minimum Supported Rust Version (MSRV)

The minimum supported Rust version for this library is 1.81.0

## License

All crates licensed under either of
- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
