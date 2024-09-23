use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use rand_core::CryptoRngCore;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Encapsulate a public key using the ECDH key exchange method.
/// This method is used for curves supported by the `EcKey` API
/// and uses OpenSSL's RNG for the ephemeral key generation.
///
/// # Arguments
///
/// * `pk` - The public key to encapsulate
/// * `group` - The EC group to use
///
/// # Returns
///
/// A tuple containing the shared secret and ciphertext (ss, ct)
pub fn encaps_ec_based(pk: &[u8], nid: Nid) -> Result<(Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(nid)?;
    // pk is the public key in uncompressed form, so we need to convert it to an EcKey
    // BigNumContext should be short-lived and used only for the operations that require it
    let mut ctx = BigNumContext::new()?;
    let pk_point = EcPoint::from_bytes(&group, pk, &mut ctx)?;

    // Create the public key
    let key = EcKey::from_public_key(&group, &pk_point)?;
    let pk: PKey<openssl::pkey::Public> = PKey::from_ec_key(key)?;

    let (ss, ct) = {
        // Create a new ephemeral key
        let ephemeral_key = EcKey::generate(&group)?;
        let es = PKey::from_ec_key(ephemeral_key.clone())?;
        let mut deriver = Deriver::new(&es)?;
        deriver.set_peer(&pk)?;
        let ss = deriver.derive_to_vec()?;
        // Public key should be uncompressed point as octet string
        let ct = ephemeral_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        (ss, ct)
    };
    Ok((ss, ct))
}

/// Encapsulate a public key using PKey API
/// This method is used for X25519 and X448 which are not supported by the `EcKey` API.
/// It uses OpenSSL's RNG for the ephemeral key generation.
///
/// # Arguments
///
/// * `pk` - The public key to encapsulate
/// * `id` - The ID of the curve (X25519 or X448)
///
/// # Returns
///
/// A tuple containing the shared secret and ciphertext (ss, ct)
pub fn encaps_pkey_based(pk: &[u8], id: Id) -> Result<(Vec<u8>, Vec<u8>)> {
    let (_, esk) = get_key_pair_pkey_based(id)?;
    let esk = PKey::private_key_from_raw_bytes(&esk, id)?;
    let pk = PKey::public_key_from_raw_bytes(pk, id)?;
    let mut deriver = Deriver::new(&esk)?;
    deriver.set_peer(&pk)?;
    let ss = deriver.derive_to_vec()?;
    let ct = esk.raw_public_key()?;
    Ok((ss, ct))
}

/// Get an EC key using the EcKey API
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `group` - The EC group
/// * `sk` - The secret key
///
/// # Returns
///
/// The EC key
pub fn get_ec_key_from_sk(id: Nid, sk: &[u8]) -> Result<EcKey<Private>> {
    let ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(id)?;
    // sk is the secret key in octet string form
    let sk_n = BigNum::from_slice(sk)?;
    let pk_p = compute_public_key(&ctx, &group, &sk_n)?;
    let sk = EcKey::from_private_components(&group, &sk_n, &pk_p)?;
    Ok(sk)
}

pub fn get_ec_key_from_pk(id: Nid, pk: &[u8]) -> Result<EcKey<Public>> {
    let group = EcGroup::from_curve_name(id)?;
    let mut ctx = BigNumContext::new()?;
    // pk is the public key in uncompressed form
    let pk_point = EcPoint::from_bytes(&group, pk, &mut ctx)?;
    let pk = EcKey::from_public_key(&group, &pk_point)?;
    Ok(pk)
}

/// Decapsulate a ciphertext using the EcKey API
///
/// # Arguments
///
/// * `sk` - The secret key to decapsulate with
/// * `ct` - The ciphertext to decapsulate
/// * `group` - The EC group to use
///
/// # Returns
///
/// The shared secret
pub fn decaps_ec_based(sk: &[u8], ct: &[u8], nid: Nid) -> Result<Vec<u8>> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(nid)?;

    let sk = get_ec_key_from_sk(nid, sk)?;

    // ct is the public key in uncompressed form
    let ct_point = EcPoint::from_bytes(&group, ct, &mut ctx)?;
    let ct = EcKey::from_public_key(&group, &ct_point)?;

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
/// * `id` - The ID of the curve (X25519 or X448)
///
/// # Returns
/// The shared secret
pub fn decaps_pkey_based(sk: &[u8], ct: &[u8], id: Id) -> Result<Vec<u8>> {
    // Apply clamping
    let mut sk = sk.to_vec();
    clamp_pkey_based_sk(&mut sk, id);

    let sk = PKey::private_key_from_raw_bytes(&sk, id)?;
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
fn pad_bignum_to_length(bn: &BigNumRef, desired_length: usize) -> Vec<u8> {
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

/// Get the byte length of the secret key for an EC curve (EcKey API)
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

/// Get a secret key as a BigNum for an EC curve (ECKey API)
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `rng` - A random number generator
/// * `group` - The EC group
///
/// # Returns
///
/// The secret key as a BigNum
fn get_sk_bignum_ec_based(
    ctx: &mut BigNumContext,
    mut rng: impl CryptoRngCore,
    group: &EcGroup,
) -> Result<BigNum> {
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

/// Get the public and secret keys as byte vectors from a BigNum private key.
/// This method is used for curves supported by the `EcKey` API.
///
/// # Arguments
///
/// * `ctx` - The BigNumContext
/// * `private_key_bn` - The private key as a BigNum
/// * `group` - The EC group
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) as uncompressed point and field element bytes
/// respectively. The secret key is padded to the byte length of the order of the group.
fn get_pk_sk_from_bignum_ec_based(
    ctx: &mut BigNumContext,
    private_key_bn: &BigNumRef,
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

/// Get a key pair using the OpenSSL library (default RNG) for an EC curve
/// that is supported by the `EcKey` API.
///
/// # Arguments
///
/// * `group` - The EC group
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) with pk as an uncompressed point
/// and sk as a field element bytes
pub fn get_key_pair_ec_based(nid: Nid) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&group)?;
    let private_key_bn = ec_key.private_key();
    get_pk_sk_from_bignum_ec_based(&mut ctx, private_key_bn, &group)
}

/// Get an EC key pair but specify the RNG to use
///
/// # Arguments
///
/// * `rng` - The random number generator
/// * `group` - The EC group
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) with pk as an uncompressed point
/// and sk as a field element bytes
pub fn get_key_pair_ec_based_with_rng(
    rng: &mut impl CryptoRngCore,
    nid: Nid,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ctx = BigNumContext::new()?;

    let group = EcGroup::from_curve_name(nid)?;

    // Get a big num as private key
    let private_key_bn = get_sk_bignum_ec_based(&mut ctx, rng, &group)?;
    let private_key_bn = private_key_bn.as_ref();
    get_pk_sk_from_bignum_ec_based(&mut ctx, private_key_bn, &group)
}

/// Compute the public key from the private key for an EC curve.
/// The private key is given as a BigNum between 1 and n-1, where n is the order of the group.
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
    private_key_bn: &BigNumRef,
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

/// Get an elliptic curve key pair using a PKey based method
///
/// This is used for X448, and X25519 which are not supported by the `EcKey` API.
///
/// The default OpenSSL RNG is used.
///
/// # Arguments
///
/// * `id` - The ID of the curve
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) in DER format
pub fn get_key_pair_pkey_based(id: Id) -> Result<(Vec<u8>, Vec<u8>)> {
    let sk = match id {
        Id::X448 => PKey::generate_x448()?,
        Id::X25519 => PKey::generate_x25519()?,
        Id::ED25519 => PKey::generate_ed25519()?,
        Id::ED448 => PKey::generate_ed448()?,
        _ => panic!("Unsupported ID"),
    };

    let pk = sk.raw_public_key()?;
    let sk = sk.raw_private_key()?;
    Ok((pk, sk))
}

/// Get an elliptic curve key pair using a PKey based method. This is used for X448, and X25519
/// which are not supported by the `EcKey` API.
///
/// The RNG is specified.
///
/// # Arguments
///
/// * `rng` - The random number generator
/// * `id` - The ID of the curve (X448 or X25519)
///
/// # Returns
///
/// A tuple containing the public and secret keys (pk, sk) in DER format
pub fn get_keypair_pkey_based_with_rng(
    rng: &mut impl CryptoRngCore,
    id: Id,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate n random bytes according to the curve
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

    let sk_original = sk.clone();

    // Apply clamping
    clamp_pkey_based_sk(&mut sk, id);

    let sk_obj = PKey::private_key_from_raw_bytes(&sk, id)?;
    let pk = sk_obj.raw_public_key()?;

    Ok((pk, sk_original))
}

/// Get the public key from a secret key for an EC curve (not used currently)
///
/// # Arguments
///
/// * `sk` - The secret key
/// * `group` - The EC group
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

/// Get the public key from a secret key for a PKey based method (not used currently)
///
/// # Arguments
///
/// * `sk` - The secret key
/// * `id` - The ID of the curve
///
/// # Returns
///
/// The public key as a byte vector
#[allow(dead_code)] // This function can be used in the future
fn get_pk_from_sk_pkey_based(sk: &[u8], id: Id) -> Result<Vec<u8>> {
    let sk = PKey::private_key_from_raw_bytes(sk, id)?;
    Ok(sk.raw_public_key()?)
}

/// Sign a message using an EC based method
///
/// # Arguments
///
/// * `id` - The ID of the curve
/// * `sk` - The secret key
/// * `msg` - The message to sign
/// * `digest` - The digest to use
///
/// # Returns
///
/// The signature as a byte vector
pub fn sign_ec_based(id: Nid, sk: &[u8], msg: &[u8], digest: MessageDigest) -> Result<Vec<u8>> {
    let sk = get_ec_key_from_sk(id, sk)?;
    let pkey = PKey::from_ec_key(sk)?;
    let mut signer = openssl::sign::Signer::new(digest, &pkey)?;
    signer.update(msg)?;
    Ok(signer.sign_to_vec()?)
}

/// Sign a message using a PKey based method (used for Ed25519 and Ed448)
///
/// # Arguments
///
/// * `id` - The ID of the curve
/// * `sk` - The secret key
/// * `msg` - The message to sign
/// * `digest` - The digest to use
///
/// # Returns
///
/// The signature as a byte vector
pub fn sign_pkey_based(id: Id, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let sk = PKey::private_key_from_raw_bytes(sk, id)?;
    let mut signer = openssl::sign::Signer::new_without_digest(&sk)?;
    Ok(signer.sign_oneshot_to_vec(msg)?)
}

/// Verify a signature using an EC based method
///
/// # Arguments
///
/// * `id` - The ID of the curve
/// * `pk` - The public key
/// * `msg` - The message
/// * `signature` - The signature
/// * `digest` - The digest to use
///
/// # Returns
///
/// A boolean indicating if the signature is valid
pub fn verify_ec_based(
    id: Nid,
    pk: &[u8],
    msg: &[u8],
    signature: &[u8],
    digest: MessageDigest,
) -> Result<bool> {
    let ec_key = get_ec_key_from_pk(id, pk)?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)?;
    let mut v = openssl::sign::Verifier::new(digest, &pkey)?;
    v.update(msg)?;
    Ok(v.verify(signature)?)
}

/// Verify a signature using a PKey based method
///
/// # Arguments
///
/// * `id` - The ID of the curve
/// * `pk` - The public key
/// * `msg` - The message
/// * `signature` - The signature
/// * `digest` - The digest to use
///
/// # Returns
///
/// A boolean indicating if the signature is valid
pub fn verify_pkey_based(id: Id, pk: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
    let pkey = PKey::public_key_from_raw_bytes(pk, id)?;
    let mut v = openssl::sign::Verifier::new_without_digest(&pkey)?;
    Ok(v.verify_oneshot(signature, msg)?)
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
            let (ss, ct) = encaps_ec_based(&pk, *nid).unwrap();
            let ss2 = decaps_ec_based(&sk, &ct, *nid).unwrap();
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
            let (ss, ct) = encaps_ec_based(&pk, *nid).unwrap();
            let ss2 = decaps_ec_based(&sk, &ct, *nid).unwrap();
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
        let ss2 = decaps_pkey_based(&sk, &ct, Id::X25519).unwrap();

        assert_eq!(ss, ss2);

        // Now test with a sk with all bits set
        let mut sk = [0xff; 32];
        clamp_pkey_based_sk(&mut sk, Id::X25519);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X25519).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X25519).unwrap();
        let ss2 = decaps_pkey_based(&sk, &ct, Id::X25519).unwrap();

        assert_eq!(ss, ss2);
    }

    #[test]
    fn test_boundary_x448() {
        let mut sk = [0u8; 56];
        clamp_pkey_based_sk(&mut sk, Id::X448);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X448).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X448).unwrap();
        let ss2 = decaps_pkey_based(&sk, &ct, Id::X448).unwrap();

        assert_eq!(ss, ss2);

        // Now test with a sk with all bits set
        let mut sk = [0xff; 56];
        clamp_pkey_based_sk(&mut sk, Id::X448);

        let sk_obj = PKey::private_key_from_raw_bytes(&sk, Id::X448).unwrap();
        let pk = sk_obj.raw_public_key().unwrap();

        let (ss, ct) = encaps_pkey_based(&pk, Id::X448).unwrap();
        let ss2 = decaps_pkey_based(&sk, &ct, Id::X448).unwrap();

        assert_eq!(ss, ss2);
    }
}
