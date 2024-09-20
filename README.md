# PQC

This is a collection of post-quantum cryptographic algorithms implemented in Rust.

## Composite ML-KEM for Use in the Internet X.509 Public Key Infrastructure and CMS

A set of [Key Encapsulation Mechanism](https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html) (KEM) schemes that use pairs of cryptographic elements such as public keys and cipher texts to combine their security properties. These schemes effectively mitigate risks associated with the adoption of post-quantum cryptography and are fully compatible with existing X.509, PKIX, and CMS data structures and protocols.

### Open Questions

- [❓] What is the ASN.1 format of composite public keys from `CompositeKEM.KeyGen()`?
    The draft specifies:
    </br></br>
    The KeyGen() -> (pk, sk) of a composite KEM algorithm will perform the KeyGen() of the respective component KEM algorithms and it produces a composite public key pk as per Section 3.2

    ```
    CompositeKEM.KeyGen():
        (compositePK[0], compositeSK[0]) = MLKEM.KeyGen()
        (compositePK[1], compositeSK[1]) = TradKEM.KeyGen()

        return (compositePK, compositeSK)
    ```

    Section 3.2 specifies:
    ```
    CompositeKEMPublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
    ```
    Are the two component public keys raw public keys without any OIDs? Are they the output of the component KEM KeyGen() functions?

- [❓] What is the ASN.1 format of composite secret keys from `CompositeKEM.KeyGen()`?
    The draft specifies:
    </br></br>
    The KeyGen() -> (pk, sk) of a composite KEM algorithm will perform the KeyGen() of the respective component KEM algorithms and it produces a composite private key pk as per Section 3.3
    ```
    CompositeKEM.KeyGen():
        (compositePK[0], compositeSK[0]) = MLKEM.KeyGen()
        (compositePK[1], compositeSK[1]) = TradKEM.KeyGen()

        return (compositePK, compositeSK)
    ```

    Section 3.3 specifies:
    ```
    CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
    ```

    `OneAsymmetricKey` is defined in [RFC5912](https://tools.ietf.org/html/rfc5912) as:
    ```
    OneAsymmetricKey ::= SEQUENCE {
        version Version,
        privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
        privateKey PrivateKey,
        attributes [0] Attributes OPTIONAL,
        ...,
        [[2: publicKey [1] PublicKey OPTIONAL ]],
        ...
    }
    ```

    So, the composite private key is a sequence of two `OneAsymmetricKey` structures. What are the OID values for the `privateKeyAlgorithm` fields of the two `OneAsymmetricKey` structures?

    We assume the OID values are the same as the OID values of the component KEM algorithms - i.e:

    For elliptic curve component KEM:
    ```
    KemType::P256 => "1.2.840.10045.3.1.7".to_string(),
    KemType::P384 => "1.3.132.0.34".to_string(),
    // RFC 8410
    KemType::X25519 => "1.3.101.110".to_string(),
    KemType::X448 => "1.3.101.110".to_string(),
    // RFC 5639
    KemType::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.7".to_string(),
    KemType::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.11".to_string(),
    ```

    For RSA component KEM:
    ```
    KemType::RsaOAEP2048 => "1.2.840.113549.1.1.7".to_string(),
    KemType::RsaOAEP3072 => "1.2.840.113549.1.1.7".to_string(),
    KemType::RsaOAEP4096 => "1.2.840.113549.1.1.7".to_string(),
    ```

    For ML-KEM component KEM:
    ```
    KemType::MlKem512 => "2.16.840.1.101.3.4.4.1".to_string(),
    KemType::MlKem768 => "2.16.840.1.101.3.4.4.2".to_string(),
    KemType::MlKem1024 => "2.16.840.1.101.3.4.4.3".to_string(),
    ```

- [❓] What is the ASN.1 format of RSA keys?

- [❓] Why do we need `CompositeKEM.Decap(ct, mlkemSK, tradSK)` as a signature, why not just use the composite  Secret Key and implement `CompositeKEM.Decap(ct, compositeSK)`?














