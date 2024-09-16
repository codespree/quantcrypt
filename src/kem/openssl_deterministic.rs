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
    let key = EcKey::public_key_from_der(pk).unwrap();
    let pk: PKey<openssl::pkey::Public> = PKey::from_ec_key(key).unwrap();

    let (ct, ss) = {
        // Create a new ephemeral key
        let ephemeral_key = EcKey::generate(group).unwrap();
        let es = PKey::from_ec_key(ephemeral_key.clone()).unwrap();
        let mut deriver = Deriver::new(&es).unwrap();
        deriver.set_peer(&pk).unwrap();
        let ss = deriver.derive_to_vec().unwrap();
        let ct = es.public_key_to_der().unwrap();
        if ss.len() != 32 {
            // Handle the error if the length is incorrect
            println!("Encapsulate: Unexpected shared secret length: {}", ss.len());
        }
        (ct, ss)
    };
    Ok((ct, ss))
}

pub fn decaps_ossl(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let sk = EcKey::private_key_from_der(sk).unwrap();
    let ct = EcKey::public_key_from_der(ct).unwrap();
    let sk = PKey::from_ec_key(sk).unwrap();
    let ct = PKey::from_ec_key(ct).unwrap();
    let mut deriver = Deriver::new(&sk).unwrap();
    deriver.set_peer(&ct).unwrap();
    let ss = deriver.derive_to_vec().unwrap();
    if ss.len() != 32 {
        // Handle the error if the length is incorrect
        println!("Decapsulate: Unexpected shared secret length: {}", ss.len());
    }
    Ok(ss)
}

pub fn get_key_pair_ossl(seed: Option<&[u8; 32]>, group: &EcGroup) -> (Vec<u8>, Vec<u8>) {
    let mut rng = if let Some(seed) = seed {
        ChaCha20Rng::from_seed(*seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Generate 32 random bytes representing a big number
    let mut private_key_bytes = [0u8; 32];
    rng.fill_bytes(&mut private_key_bytes);

    // Convert the random bytes to a BigNum
    let private_key_bn = BigNum::from_slice(&private_key_bytes).unwrap();

    // Get the order (n) of the group
    let mut ctx = BigNumContext::new().unwrap();
    let mut order = BigNum::new().unwrap();
    group.order(&mut order, &mut ctx).unwrap();

    // Compute n - 1
    let mut n_minus_1 = BigNum::new().unwrap();
    n_minus_1
        .checked_sub(&order, &BigNum::from_u32(1).unwrap())
        .unwrap();

    // Ensure private_key_bn is in the range [1, n-1]
    // private_key_bn = (private_key_bn % (n - 1)) + 1
    let mut temp_bn = BigNum::new().unwrap();
    temp_bn
        .nnmod(&private_key_bn, &n_minus_1, &mut ctx)
        .unwrap();

    // Add 1 to the result
    let mut private_number = BigNum::new().unwrap();
    private_number
        .checked_add(&temp_bn, &BigNum::from_u32(1).unwrap())
        .unwrap();

    // Create the public key point by multiplying the generator by the private number
    let pk_point = compute_public_key(&ctx, group, &private_number).unwrap();

    // Create the EC_KEY
    let sk = EcKey::from_private_components(group, &private_number, &pk_point).unwrap();

    let pk = sk.public_key_to_der().unwrap().to_vec();
    let sk = sk.private_key_to_der().unwrap().to_vec();

    (pk, sk)
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
