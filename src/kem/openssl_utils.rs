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
    let mut rng = if let Some(seed) = seed {
        ChaCha20Rng::from_seed(*seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Get the order (n) of the group
    let mut ctx = BigNumContext::new()?;
    let mut order = BigNum::new()?;
    group.order(&mut order, &mut ctx)?;

    // Get the bit length and byte length of the order
    let bit_len = order.num_bits();
    let byte_len = ((bit_len + 7) / 8) as usize;

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

    // Create the public key point by multiplying the generator by the private number
    let pk_point = compute_public_key(&ctx, group, &private_key_bn)?;

    // Create the EC_KEY (just test validity)
    EcKey::from_private_components(group, &private_key_bn, &pk_point)?;

    // Public key should be uncompressed point as octet string
    let pks = pk_point.to_bytes(
        group,
        openssl::ec::PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?;

    // Secret key should be field element as octet string
    let sks = private_key_bn.to_vec();

    Ok((pks, sks))
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

pub fn clamp_pkey_based_sk(sk: &mut [u8], id: Id) {
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
