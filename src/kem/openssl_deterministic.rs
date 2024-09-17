use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::PKey;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error;

// Change the alias to use `Box<dyn error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub fn encaps_ossl(pk: &[u8], group: &EcGroup) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = EcKey::public_key_from_der(pk)?;
    let pk: PKey<openssl::pkey::Public> = PKey::from_ec_key(key)?;

    let (ct, ss) = {
        // Create a new ephemeral key
        let ephemeral_key = EcKey::generate(group)?;
        let es = PKey::from_ec_key(ephemeral_key.clone())?;
        let mut deriver = Deriver::new(&es)?;
        deriver.set_peer(&pk)?;
        let ss = deriver.derive_to_vec()?;
        let ct = es.public_key_to_der()?;
        if ss.len() != 32 {
            // Handle the error if the length is incorrect
            println!("Encapsulate: Unexpected shared secret length: {}", ss.len());
        }
        (ct, ss)
    };
    Ok((ct, ss))
}

pub fn decaps_ossl(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let sk = EcKey::private_key_from_der(sk)?;
    let ct = EcKey::public_key_from_der(ct)?;
    let sk = PKey::from_ec_key(sk)?;
    let ct = PKey::from_ec_key(ct)?;
    let mut deriver = Deriver::new(&sk)?;
    deriver.set_peer(&ct)?;
    let ss = deriver.derive_to_vec()?;
    if ss.len() != 32 {
        // Handle the error if the length is incorrect
        println!("Decapsulate: Unexpected shared secret length: {}", ss.len());
    }
    Ok(ss)
}

pub fn get_key_pair_ossl(seed: Option<&[u8; 32]>, group: &EcGroup) -> Result<(Vec<u8>, Vec<u8>)> {
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

    // Create the EC_KEY
    let sk = EcKey::from_private_components(group, &private_key_bn, &pk_point)?;

    let pk = sk.public_key_to_der()?.to_vec();
    let sk = sk.private_key_to_der()?.to_vec();

    Ok((pk, sk))
}

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
