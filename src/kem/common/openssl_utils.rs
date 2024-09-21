use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::{Id, PKey};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Encapsulate a public key using the ECDH key exchange method
///
/// # Arguments
///
/// * `pk` - The public key to encapsulate
/// * `group` - The EC group to use
///
/// # Returns
///
/// A tuple containing the shared secret and ciphertext (ss, ct)
pub fn encaps_ec_based(pk: &[u8], group: &EcGroup) -> Result<(Vec<u8>, Vec<u8>)> {
    // pk is the public key in uncompressed form, so we need to convert it to an EcKey
    // TODO: Should BignumContext be reused?
    let mut ctx = BigNumContext::new()?;
    let pk_point = EcPoint::from_bytes(group, pk, &mut ctx)?;

    // Create the public key
    let key = EcKey::from_public_key(group, &pk_point)?;
    let pk: PKey<openssl::pkey::Public> = PKey::from_ec_key(key)?;

    let (ss, ct) = {
        // Create a new ephemeral key
        let ephemeral_key = EcKey::generate(group)?;
        let es = PKey::from_ec_key(ephemeral_key.clone())?;
        let mut deriver = Deriver::new(&es)?;
        deriver.set_peer(&pk)?;
        let ss = deriver.derive_to_vec()?;
        // Public key should be uncompressed point as octet string
        let ct = ephemeral_key.public_key().to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        (ss, ct)
    };
    Ok((ss, ct))
}

/// Encapsulate a public key using PKey API
/// This method is used for X25519 and X448 which are not supported by the `EcKey` API.
///
/// # Arguments
///
/// * `pk` - The public key to encapsulate
///
/// # Returns
///
/// A tuple containing the shared secret and ciphertext (ss, ct)
pub fn encaps_pkey_based(pk: &[u8], id: Id) -> Result<(Vec<u8>, Vec<u8>)> {
    let (_, esk) = get_keypair_pkey_based(None, id)?;
    let esk = PKey::private_key_from_raw_bytes(&esk, id)?;
    let pk = PKey::public_key_from_raw_bytes(pk, id)?;
    let mut deriver = Deriver::new(&esk)?;
    deriver.set_peer(&pk)?;
    let ss = deriver.derive_to_vec()?;
    let ct = esk.raw_public_key()?;
    Ok((ss, ct))
}

/// Decapsulate a ciphertext using the ECDH key exchange method
///
/// # Arguments
///
/// * `sk` - The secret key to decapsulate with
/// * `ct` - The ciphertext to decapsulate
///
/// # Returns
///
/// The shared secret
pub fn decaps_ec_based(sk: &[u8], ct: &[u8], group: &EcGroup) -> Result<Vec<u8>> {
    let mut ctx = BigNumContext::new()?;

    // sk is the secret key in octet string form
    let sk_n = BigNum::from_slice(sk)?;
    let pk_p = compute_public_key(&ctx, group, &sk_n)?;
    let sk = EcKey::from_private_components(group, &sk_n, &pk_p)?;

    // ct is the public key in uncompressed form
    let ct_point = EcPoint::from_bytes(group, ct, &mut ctx)?;
    let ct = EcKey::from_public_key(group, &ct_point)?;

    let sk = PKey::from_ec_key(sk)?;
    let ct = PKey::from_ec_key(ct)?;
    let mut deriver = Deriver::new(&sk)?;
    deriver.set_peer(&ct)?;
    let ss = deriver.derive_to_vec()?;
    Ok(ss)
}

/// Decapsulate a ciphertext using the PKey API
/// This method is used for X25519 and X448 which are not supported by the `EcKey` API.
///
/// # Arguments
///
/// * `sk` - The secret key to decapsulate with
/// * `ct` - The ciphertext to decapsulate
///
/// # Returns
/// The shared secret
pub fn decaps_pkey_based_ossl(sk: &[u8], ct: &[u8], id: Id) -> Result<Vec<u8>> {
    let sk = PKey::private_key_from_raw_bytes(sk, id)?;
    let ct = PKey::public_key_from_raw_bytes(ct, id)?;
    let mut deriver = Deriver::new(&sk)?;
    deriver.set_peer(&ct)?;
    let ss = deriver.derive_to_vec()?;
    Ok(ss)
}

/// Pad a BigNum to a desired length (with leading zeros)
///
/// # Arguments
///
/// * `bn` - The BigNum to pad
/// * `desired_length` - The desired length of the padded BigNum
///
/// # Returns
///
/// The padded BigNum as a byte vector
fn pad_bignum_to_length(bn: &BigNum, desired_length: usize) -> Vec<u8> {
    let bn_bytes = bn.to_vec();
    if bn_bytes.len() > desired_length {
        panic!("BigNum is already larger than desired length");
    }

    let padding_needed = desired_length - bn_bytes.len();
    let mut padded_bn_bytes = Vec::with_capacity(desired_length);
    padded_bn_bytes.extend(std::iter::repeat(0u8).take(padding_needed));
    padded_bn_bytes.extend_from_slice(&bn_bytes);

    padded_bn_bytes
}

/// Get the byte length of the secret key for an EC curve
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `group` - The EC group
///
/// # Returns
///
/// The byte length of the secret key
fn get_sk_byte_len_ec_based(ctx: &mut BigNumContext, group: &EcGroup) -> Result<usize> {
    // Get the order (n) of the group
    let mut order = BigNum::new()?;
    group.order(&mut order, ctx)?;

    let bit_len = order.num_bits();
    let byte_len = ((bit_len + 7) / 8) as usize;

    Ok(byte_len)
}

/// Get a secret key as a BigNum for an EC curve
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `seed` - An optional 32-byte seed
/// * `group` - The EC group
///
/// # Returns
///
/// The secret key as a BigNum
fn get_sk_bignum_ec_based(
    ctx: &mut BigNumContext,
    seed: Option<&[u8; 32]>,
    group: &EcGroup,
) -> Result<BigNum> {
    let mut rng = if let Some(seed) = seed {
        ChaCha20Rng::from_seed(*seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Get the order (n) of the group
    let mut order = BigNum::new()?;
    group.order(&mut order, ctx)?;

    // Get the byte length of the order
    let byte_len = get_sk_byte_len_ec_based(ctx, group)?;

    let private_key_bn = loop {
        // Generate byte_len random bytes, the associated BigNum may
        // be larger than the order, so we need to check that it is
        let mut private_key_bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut private_key_bytes);

        // Convert private key bytes to BigNum
        let d_candidate = BigNum::from_slice(&private_key_bytes)?;

        // If d_candidate >= 1 && d_candidate < n, accept it
        if d_candidate >= BigNum::from_u32(1)? && d_candidate < order {
            break d_candidate;
        }
        // Otherwise, discard and try again
    };
    Ok(private_key_bn)
}

/// Get the public and secret keys as byte vectors from a BigNum private key
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `private_key_bn` - The private key as a BigNum
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) as uncompressed point and field element octets
fn get_pk_sk_from_bignum_ec_based(
    ctx: &mut BigNumContext,
    private_key_bn: &BigNum,
    group: &EcGroup,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Create the public key point by multiplying the generator by the private number
    let pk_point = compute_public_key(ctx, group, private_key_bn)?;

    // Create the EC_KEY (just test validity)
    EcKey::from_private_components(group, private_key_bn, &pk_point)?;

    // Public key should be uncompressed point as octet string
    let pks = pk_point.to_bytes(group, openssl::ec::PointConversionForm::UNCOMPRESSED, ctx)?;

    let byte_len = get_sk_byte_len_ec_based(ctx, group)?;

    // Secret key should be field element as octet string
    let sks = pad_bignum_to_length(private_key_bn, byte_len);

    Ok((pks, sks))
}

/// Get an EC key pair using the OpenSSL library
///
/// # Arguments
///
/// * `seed` - An optional 32-byte seed
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) in DER format
pub fn get_key_pair_ec_based(
    seed: Option<&[u8; 32]>,
    group: &EcGroup,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ctx = BigNumContext::new()?;

    // Get a big num as private key
    let private_key_bn = get_sk_bignum_ec_based(&mut ctx, seed, group)?;
    get_pk_sk_from_bignum_ec_based(&mut ctx, &private_key_bn, group)
}

/// Compute the public key from the private key for an EC curve
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `group` - The EC group
/// * `private_key_bn` - The private key as a BigNum
///
/// # Returns
///
/// The public key as an EC_POINT
fn compute_public_key(
    ctx: &BigNumContext,
    group: &EcGroup,
    private_key_bn: &BigNum,
) -> Result<EcPoint> {
    // Create a new EC_POINT
    let mut public_key_point = EcPoint::new(group)?;

    // Get the generator for the group
    let generator = group.generator();

    // Get the public key point
    public_key_point.mul(group, generator, private_key_bn, ctx)?;

    Ok(public_key_point)
}

/// Clamp a private key for X448 or X25519
///
/// # Arguments
///
/// * `sk` - The secret key to clamp
/// * `id` - The ID of the curve
///
/// # Panics
///
/// Panics if the ID is not X448 or X25519
fn clamp_pkey_based_sk(sk: &mut [u8], id: Id) {
    match id {
        Id::X448 => {
            sk[0] &= 252;
            sk[55] |= 128;
        }
        Id::X25519 => {
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
        }
        _ => panic!("Unsupported ID"),
    }
}

/// Get an elliptic curve key pair using a PKey based method. This is used for X448, and X25519
/// which are not supported by the `EcKey` API.
///
/// # Arguments
///
/// * `seed` - An optional 32-byte seed
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) in DER format
pub fn get_keypair_pkey_based(seed: Option<&[u8; 32]>, id: Id) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = if let Some(seed) = seed {
        ChaCha20Rng::from_seed(*seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Generate 56 random bytes
    let mut sk = match id {
        Id::X448 => {
            let mut sk: [u8; 56] = [0; 56];
            rng.fill_bytes(&mut sk);
            sk.to_vec()
        }
        Id::X25519 => {
            let mut sk: [u8; 32] = [0; 32];
            rng.fill_bytes(&mut sk);
            sk.to_vec()
        }
        _ => panic!("Unsupported ID"),
    };

    // Apply clamping
    clamp_pkey_based_sk(&mut sk, id);

    let sk_obj = PKey::private_key_from_raw_bytes(&sk, id)?;
    let pk = sk_obj.raw_public_key()?;

    Ok((pk, sk))
}

/// Get the public key from a secret key for an EC curve
///
/// # Arguments
///
/// * `sk` - The secret key
///
/// # Returns
///
/// The public key as a byte vector from an uncompressed point
#[allow(dead_code)] // This function can be used in the future
pub fn get_pk_from_sk_ec_based(sk: &[u8], group: &EcGroup) -> Result<Vec<u8>> {
    let mut ctx = BigNumContext::new()?;
    let private_key_bn = BigNum::from_slice(sk)?;
    let pk_point = compute_public_key(&ctx, group, &private_key_bn)?;
    Ok(pk_point.to_bytes(
        group,
        openssl::ec::PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?)
}

/// Get the public key from a secret key for a PKey based method
///
/// # Arguments
///
/// * `sk` - The secret key
///
/// # Returns
///
/// The public key as a byte vector
#[allow(dead_code)] // This function can be used in the future
pub fn get_pk_from_sk_pkey_based(sk: &[u8], id: Id) -> Result<Vec<u8>> {
    let sk = PKey::private_key_from_raw_bytes(sk, id)?;
    Ok(sk.raw_public_key()?)
}

#[cfg(test)]
mod tests {
    use openssl::nid::Nid;

    use super::*;
    #[test]
    fn test_pad_bignum_to_length() {
        let bn = BigNum::from_u32(0x1234).unwrap();
        let padded_bn = pad_bignum_to_length(&bn, 4);
        assert_eq!(padded_bn, vec![0, 0, 0x12, 0x34]);
    }

    #[test]
    fn test_boundary_ec() {
        let nids = [
            Nid::X9_62_PRIME256V1,
            Nid::SECP384R1,
            Nid::BRAINPOOL_P256R1,
            Nid::BRAINPOOL_P384R1,
        ];

        let mut ctx = BigNumContext::new().unwrap();

        for nid in nids.iter() {
            let group = EcGroup::from_curve_name(*nid).unwrap();

            // Use a private number which is 1
            let private_key_bn = BigNum::from_u32(1).unwrap();
            let (pk, sk) =
                get_pk_sk_from_bignum_ec_based(&mut ctx, &private_key_bn, &group).unwrap();
            let (ss, ct) = encaps_ec_based(&pk, &group).unwrap();
            let ss2 = decaps_ec_based(&sk, &ct, &group).unwrap();
            assert_eq!(ss, ss2);

            // Use a private number which is order - 1
            let mut order = BigNum::new().unwrap();
            group.order(&mut order, &mut ctx).unwrap();

            let mut private_key_bn = BigNum::new().unwrap();
            private_key_bn
                .checked_sub(&order, &BigNum::from_u32(1).unwrap())
                .unwrap();

            let (pk, sk) =
                get_pk_sk_from_bignum_ec_based(&mut ctx, &private_key_bn, &group).unwrap();
            let (ss, ct) = encaps_ec_based(&pk, &group).unwrap();
            let ss2 = decaps_ec_based(&sk, &ct, &group).unwrap();
            assert_eq!(ss, ss2);
        }
    }

    #[test]
    fn test_boundary_x25519() {
        let mut sk = [0u8; 32];
        clamp_pkey_based_sk(&mut sk, Id::X25519);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X25519).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X25519).unwrap();
        let ss2 = decaps_pkey_based_ossl(&sk, &ct, Id::X25519).unwrap();

        assert_eq!(ss, ss2);

        // Now test with a sk with all bits set
        let mut sk = [0xff; 32];
        clamp_pkey_based_sk(&mut sk, Id::X25519);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X25519).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X25519).unwrap();
        let ss2 = decaps_pkey_based_ossl(&sk, &ct, Id::X25519).unwrap();

        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_boundary_x448() {
        let mut sk = [0u8; 56];
        clamp_pkey_based_sk(&mut sk, Id::X448);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X448).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X448).unwrap();
        let ss2 = decaps_pkey_based_ossl(&sk, &ct, Id::X448).unwrap();

        assert_eq!(ss, ss2);

        // Now test with a sk with all bits set
        let mut sk = [0xff; 56];
        clamp_pkey_based_sk(&mut sk, Id::X448);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X448).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X448).unwrap();
        let ss2 = decaps_pkey_based_ossl(&sk, &ct, Id::X448).unwrap();

        assert_eq!(ss, ss2);
    }
}
