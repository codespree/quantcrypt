
# ML-DSA Key Length Summary

| DSA | Traditional Composite | Npk | Nsk | sig_len |
| --- | -------------------- | --- | --- | ------- |
| ML-DSA44 | <N.A> | 1312 | 2560 | 2420 |
| ML-DSA44 | Ed25519SHA512 | 1356 | 2634 | 2690 |
| ML-DSA44 | EcdsaP256SHA256 | 1389 | 2639 | 2690 |
| ML-DSA44 | EcdsaBrainpoolP256r1SHA256 | 1389 | 2639 | 2496 |
| ML-DSA65 | <N.A> | 1952 | 4032 | 3309 |
| ML-DSA65 | EcdsaP256SHA512 | 2029 | 4111 | 3707 |
| ML-DSA65 | EcdsaBrainpoolP256r1SHA512 | 2029 | 4111 | 3707 |
| ML-DSA65 | Ed25519SHA512 | 1996 | 4106 | 3385 |
| ML-DSA87 | <N.A> | 2592 | 4896 | 4627 |
| ML-DSA87 | EcdsaP384SHA512 | 2701 | 4991 | <N.A> |
| ML-DSA87 | EcdsaBrainpoolP384r1SHA512 | 2701 | 4991 | <N.A> |
| ML-DSA87 | Ed448SHA512 | 2661 | 4995 | 4753 |

## Notes on Overhead Computation

The full derivation of the aforementioned lengths can be found in the `common::config` folder of the DSA folder. As a general guideline, below are some overhead computations:

- **Overhead of a BIT STRING** = Tag + Length + Unused Bits.  
    - Short-form length (<=127 bytes) => 1 + 1 + 1 = 3  
    - Long-form length (> 127 bytes) => 1 + 3 + 1 = 5  

- **Overhead of a SEQUENCE** = Tag + Length (of all its content including overheads).  
    - Short-form length (<=127 bytes) => 1 + 1 = 2  
    - Long-form length (> 127 bytes) => 1 + 3 = 4  

### PublicKey

```plaintext
SEQUENCE {
    pq_pk BIT STRING,  
    trad_pk BIT STRING,
}
```

Overhead of a SEQUENCE SIZE (2) OF BIT STRING (one short-form, one long form) = 5 + 3 + 4 = 12 

Overhead of a SEQUENCE SIZE (2) OF BIT STRING (two long form) = 5 + 5 + 4 = 14 

### SecretKey

```plaintext
SEQUENCE {
    pq_sk OneAsymmetricKey,  
    trad_sk OneAsymmetricKey,
}
```

### OneAsymmetricKey

```plaintext
SEQUENCE {
    privateKeyAlgorithm AlgorithmIdentifier,
    privateKey PrivateKey,
    publicKey Optional<BitString>, always None for DSA
}
```

Overhead of an OneAsymmetricKey (OAK) without a public key for a long private key:  

- (outer sequence overhead => 1(tag) + 3(length in long form)) = 4  
- (private key => 1(tag) + 3(long-form length)) = 4  
- (privateKeyAlgorithm => 1(tag) + <oid_bytes> + 2 (inner sequence, short_form length)) = 3 + <oid_bytes>  

Total = 11 + <oid_bytes>

For ML-KEM: `<oid_bytes> = 13`, so the overhead = 13 + 11 = 24

### Overhead of an OneAsymmetricKey (OAK) without a public key for a short private key:

- (outer sequence overhead => 1(tag) + 3(length in long form)) = 4  
- (private key => 1(tag) + 1(short-form length)) = 4  
- (privateKeyAlgorithm => 1(tag) + <oid_bytes> + 2 (inner sequence, short_form length)) = 3 + <oid_bytes>  

Total = 9 + <oid_bytes>

### Calculation Results for varied `<oid_bytes>` in DSA Composites:

| Traditional Algorithm | Oid | Number of Bytes | Overhead |
| --------------------- | --- | --------------- | -------- |
| Ed25519SHA512 | 1.3.101.112 | 5 | 9 + 5 = 14 |
| Ed448SHA512 | 1.3.101.113 | 5 | 9 + 5 = 14 |
| EcdsaBrainpoolP256r1SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaBrainpoolP384r1SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaP256SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |
| EcdsaP384SHA512 | 1.2.840.10045.4.3.4 | 10 | 9 + 10 = 19 |