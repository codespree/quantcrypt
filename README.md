# QuantCrypt

![example workflow](https://github.com/codespree/quantcrypt/actions/workflows/rust.yml/badge.svg) [![dependency status](https://deps.rs/repo/github/codespree/quantcrypt/status.svg)](https://deps.rs/repo/github/codespree/quantcrypt)

A collection of post-quantum cryptographic algorithms (and emerging standards) implemented in Rust.

## Composite ML-KEM for Use in the Internet X.509 Public Key Infrastructure and CMS

A set of [Key Encapsulation Mechanism](https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html) (KEM) schemes that use pairs of cryptographic elements such as public keys and cipher texts to combine their security properties. These schemes effectively mitigate risks associated with the adoption of post-quantum cryptography and are fully compatible with existing X.509, PKIX, and CMS data structures and protocols.

## Composite ML-DSA for use in Internet PKI

During the transition to post-quantum cryptography, there will be uncertainty as to the strength of cryptographic algorithms; we will no longer fully trust traditional cryptography such as RSA, Diffie-Hellman, DSA and their elliptic curve variants, but we will also not fully trust their post-quantum replacements until they have had sufficient scrutiny and time to discover and fix implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear. Even after the migration period, it may be advantageous for an entity's cryptographic identity to be composed of multiple public-key algorithms.

The [composite DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) schemes follow the draft standard for Composite Digital Signature Algorithms (DSA) for use in the Internet Public Key Infrastructure (PKI). These schemes are designed to be compatible with existing X.509, PKIX, and CMS data structures and protocols.

# License

All crates licensed under either of
- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

