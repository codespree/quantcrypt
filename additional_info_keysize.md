
# ML-DSA Key Length Summary

Links to lengths in the project: [pk](src/dsa/common/config/pk_len.rs), [sk](src/dsa/common/config/sk_len.rs), [sig](src/dsa/common/config/sig_len.rs)

| DSA | Traditional Algorithm  | Npk | Nsk | Nsig |
| --- | -------------------- | --- | --- | ------- |
| ML-DSA44 | <N.A> | 1312 | 2560 | 2420 |
| ML-DSA44 | Rsa2048PssSha256 | 1596 | <N.A> | 2690 |
| ML-DSA44 | Rsa2048Pkcs15Sha256 | 1596 | <N.A> | 2690 |
| ML-DSA44 | Ed25519SHA512 | 1356 | 2634 | 2496 |
| ML-DSA44 | EcdsaP256SHA256 | 1389 | 2639 | <N.A> |
| ML-DSA44 | EcdsaBrainpoolP256r1SHA256 | 1389 | 2639 | <N.A> |
| ML-DSA65 | <N.A> | 1952 | 4032 | 3309 |
| ML-DSA65 | Rsa3072PssSHA512 | 2364 | <N.A> | 3707 |
| ML-DSA65 | Rsa3072Pkcs15SHA512 | 2364 | <N.A> | 3707 |
| ML-DSA65 | EcdsaP256SHA512 | 2029 | 4111 | <N.A> |
| ML-DSA65 | EcdsaBrainpoolP256r1SHA512 | 2029 | 4111 | <N.A> |
| ML-DSA65 | Ed25519SHA512 | 1996 | 4106 | 3385 |
| ML-DSA87 | <N.A> | 2592 | 4896 | 4627 |
| ML-DSA87 | EcdsaP384SHA512 | 2701 | 4991 | <N.A> |
| ML-DSA87 | EcdsaBrainpoolP384r1SHA512 | 2701 | 4991 | <N.A> |
| ML-DSA87 | Ed448SHA512 | 2661 | 4995 | 4753 |

## ASCII Version
```
+-----------+-----------------------------+------+-------+---------+
|   DSA     | Traditional Algorithm       | Npk  |  Nsk  | Nsig    |
+-----------+-----------------------------+------+-------+---------+
| ML-DSA44  | <N.A>                       | 1312 | 2560  | 2420    |
| ML-DSA44  | Rsa2048PssSha256            | 1596 | <N.A> | 2690    |
| ML-DSA44  | Rsa2048Pkcs15Sha256         | 1596 | <N.A> | 2690    |
| ML-DSA44  | Ed25519SHA512               | 1356 | 2634  | 2496    |
| ML-DSA44  | EcdsaP256SHA256             | 1389 | 2639  | <N.A>   |
| ML-DSA44  | EcdsaBrainpoolP256r1SHA256  | 1389 | 2639  | <N.A>   |
| ML-DSA65  | <N.A>                       | 1952 | 4032  | 3309    |
| ML-DSA65  | Rsa3072PssSHA512            | 2364 | <N.A> | 3707    |
| ML-DSA65  | Rsa3072Pkcs15SHA512         | 2364 | <N.A> | 3707    |
| ML-DSA65  | EcdsaP256SHA512             | 2029 | 4111  | <N.A>   |
| ML-DSA65  | EcdsaBrainpoolP256r1SHA512  | 2029 | 4111  | <N.A>   |
| ML-DSA65  | Ed25519SHA512               | 1996 | 4106  | 3385    |
| ML-DSA87  | <N.A>                       | 2592 | 4896  | 4627    |
| ML-DSA87  | EcdsaP384SHA512             | 2701 | 4991  | <N.A>   |
| ML-DSA87  | EcdsaBrainpoolP384r1SHA512  | 2701 | 4991  | <N.A>   |
| ML-DSA87  | Ed448SHA512                 | 2661 | 4995  | 4753    |
+-----------+----------------------------+------+-------+----------+
```

# ML-KEM Key Length Summary

Links to lengths in the project: [pk](src/kem/common/config/pk_len.rs), [sk](src/kem/common/config/sk_len.rs), [ss](src/kem/common/config/ss_len.rs), [ct](src/kem/common/config/ct_len.rs)


| KEM        | Traditional Composite    |   Npk | Nsk   |    Nss   |    Nct   |
|------------|--------------------------|-------|-------|----------|----------|
| ML-KEM512  | P256                     |   877 | 1782  |       32 |      843 |
| ML-KEM512  | BrainpoolP256r1          |   877 | 1782  |       32 |      843 |
| ML-KEM512  | X25519                   |   844 | 1749  |       32 |      810 |
| ML-KEM512  | Rsa2048                  |  1084 | <N.A> |       32 |     1036 |
| ML-KEM512  | Rsa3072                  |  1084 | <N.A> |       32 |     1164 |
| ML-KEM768  | P256                     |  1261 | 2550  |       48 |     1163 |
| ML-KEM768  | BrainpoolP256r1          |  1261 | 2550  |       48 |     1163 |
| ML-KEM768  | X25519                   |  1228 | 2517  |     **48 |  ***1130 |
| *ML-KEM768 | Rsa2048                  |  1468 | <N.A> |       32 |     1356 |
| *ML-KEM768 | Rsa3072                  |  1596 | <N.A> |       32 |     1484 |
| *ML-KEM768 | Rsa4096                  |  1724 | <N.A> |       32 |     1612 |
| *ML-KEM768 | P384                     |  1293 | 2599  |       48 |     1195 |
| ML-KEM1024 | P384                     |  1677 | 3367  |       64 |     1675 |
| ML-KEM1024 | BrainpoolP384r1          |  1677 | 3367  |       64 |     1675 |
| ML-KEM1024 | X448                     |  1636 | 3334  |       64 |     1634 |

*: Only available in editor’s copy  

**: 48 given SHA3-384 in the public version. In the editor's copy it's SHA-256 and thus 32. Following the public version [here](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/04/).

*** Here the computation (kem_ct + trad_ct + overhead) = 1088 + 32 + 10 = 1130, and the composite computation logic seems to follow the editor’s copy (i.e. SHA-256 instead of SHA3-384).

## ASCII Version
```
+-----------+-----------------------+------+--------+--------+--------+
| KEM       | Traditional Composite | Npk  |   Nsk  |   Nss  |   Nct  |
+-----------+-----------------------+------+--------+--------+--------+
| ML-KEM512 | P256                  |  877 |  1782  |   32   |   843  |
| ML-KEM512 | BrainpoolP256r1       |  877 |  1782  |   32   |   843  |
| ML-KEM512 | X25519                |  844 |  1749  |   32   |   810  |
| ML-KEM512 | Rsa2048               | 1084 |  N/A   |   32   |  1036  |
| ML-KEM512 | Rsa3072               | 1084 |  N/A   |   32   |  1164  |
| ML-KEM768 | P256                  | 1261 |  2550  |   48   |  1163  |
| ML-KEM768 | BrainpoolP256r1       | 1261 |  2550  |   48   |  1163  |
| ML-KEM768 | X25519                | 1228 |  2517  | **48   | ***1130|
| *ML-KEM768| Rsa2048               | 1468 |  N/A   |   32   |  1356  |
| *ML-KEM768| Rsa3072               | 1596 |  N/A   |   32   |  1484  |
| *ML-KEM768| Rsa4096               | 1724 |  N/A   |   32   |  1612  |
| *ML-KEM768| P384                  | 1293 |  2599  |   48   |  1195  |
| ML-KEM1024| P384                  | 1677 |  3367  |   64   |  1675  |
| ML-KEM1024| BrainpoolP384r1       | 1677 |  3367  |   64   |  1675  |
| ML-KEM1024| X448                  | 1636 |  3334  |   64   |  1634  |
+-----------+-----------------------+------+--------+--------+--------+

*: Only available in editor’s copy  
**: Should be 48 given SHA3-384 in the public version. In the editor's copy it's SHA-256 and thus 32. Following the public version [here](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/04/).
*** Here the computation (kem_ct + trad_ct + overhead) = 1088 + 32 + 10 = 1130, and the composite computation logic seems to follow the editor’s copy (i.e. SHA-256 instead of SHA3-384).
```

### Notes on Overhead Computation

The following computations illustrate the overhead of common structures in ASN.1:
- **Overhead of a OCTET STRING** = Tag + Length.  
    - Short-form length (<=127 bytes) => 1 + 1 = 2  
    - Long-form length (> 127 bytes) => 1 + 3 = 4  

- **Overhead of a BIT STRING** = Tag + Length + Unused Bits.  
    - Short-form length (<=127 bytes) => 1 + 1 + 1 = 3  
    - Long-form length (> 127 bytes) => 1 + 3 + 1 = 5  

- **Overhead of a SEQUENCE** = Tag + Length (of all its content including overheads).  
    - Short-form length (<=127 bytes) => 1 + 1 = 2  
    - Long-form length (> 127 bytes) => 1 + 3 = 4  

### PublicKey ([DSA](src/dsa/common/config/pk_len.rs), [KEM](src/kem/common/config/pk_len.rs))

```plaintext
SEQUENCE {
    pq_pk BIT STRING,  
    trad_pk BIT STRING,
}
```

Overhead of a SEQUENCE SIZE (2) OF BIT STRING (one short-form, one long form) = 5 + 3 + 4 = 12 

Overhead of a SEQUENCE SIZE (2) OF BIT STRING (two long form) = 5 + 5 + 4 = 14 

### SecretKey ([DSA](src/dsa/common/config/sk_len.rs), [KEM](src/kem/common/config/sk_len.rs))

```plaintext
SEQUENCE {
    pq_sk OneAsymmetricKey,  
    trad_sk OneAsymmetricKey,
}
```

#### OneAsymmetricKey

```plaintext
SEQUENCE {
    privateKeyAlgorithm AlgorithmIdentifier,
    privateKey PrivateKey,
    publicKey Optional<BitString>, always None for DSA
}
```

#### Overhead of an OneAsymmetricKey (OAK) without a public key for a long private key:  

- (outer sequence overhead => 1(tag) + 3(long-form length)) = 4  
- (private key => 1(tag) + 3(long-form length)) = 4  
- (privateKeyAlgorithm => 1(tag) + <oid_bytes> + 2 (inner sequence, short-form length)) = 3 + <oid_bytes>  

Total = 11 + <oid_bytes>

For ML-KEM: `<oid_bytes> = 13`, so the overhead = 13 + 11 = 24

#### Overhead of an OneAsymmetricKey (OAK) without a public key for a short private key:

- (outer sequence overhead => 1(tag) + 3(long-form length)) = 4  
- (private key => 1(tag) + 1(short-form length)) = 2  
- (privateKeyAlgorithm => 1(tag) + <oid_bytes> + 2 (inner sequence, short-form length)) = 3 + <oid_bytes>  

Total = 9 + <oid_bytes>

#### Calculation Results for varied `<oid_bytes>` in DSA Composites:

| Traditional Algorithm | Oid | Number of Bytes | Overhead |
| --------------------- | --- | --------------- | -------- |
| Ed25519SHA512 | 1.3.101.112 | 5 | 9 + 5 = 14 |
| Ed448SHA512 | 1.3.101.113 | 5 | 9 + 5 = 14 |
| EcdsaBrainpoolP256r1SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaBrainpoolP384r1SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaP256SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaP384SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |

#### DSA vs KEM Secret Key Overhead Comparison

For the secret key of composite KEMs, they also store the public key of the tranditional algorithm, causing additional overheads. On the other hand, composite DSAs do not store traditional public keys so that their secret key overhead is solely due to the wrapping structures (Algorithm Identifier and SEQUENCE). 

### CipherText Length ([KEM](src/kem/common/config/ct_len.rs))
```plaintext
SEQUENCE {
    pq_ct   OCTET STRING,  
    trad_ct OCTET STRING,
}
```
As demonstrated in the [notes on overhead computation](#notes-on-overhead-computation) section, the overhead is either 10 or 12 for cipher text depending on the length of the keys: pq_tag (1) + pq_len(3, KEM is always long-form) + trad_tag (1) + trad_length(1 or 3) + Sequence(4).

### Singature Length ([DSA](src/dsa/common/config/sig_len.rs))
```plaintext
SEQUENCE {
    pq_sig BIT STRING,  
    trad_sig BIT STRING,
}
```
Similar structure to public key overhead computation: The value is either 12 or 14.
