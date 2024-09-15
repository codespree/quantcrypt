macro_rules! encapsulate {
    ($curve:ident, $curve_name:ident, $pk:expr, $rng:expr) => {{
        let pk =
            $curve::PublicKey::from_encoded_point(&$curve::EncodedPoint::from_bytes($pk)?).unwrap();
        let es: $curve::elliptic_curve::ecdh::EphemeralSecret<$curve::$curve_name> =
            $curve::elliptic_curve::ecdh::EphemeralSecret::random($rng);
        let ct = es.public_key().to_encoded_point(true).as_bytes().to_vec();
        let ss = es.diffie_hellman(&pk).raw_secret_bytes().to_vec();
        Ok((ct, ss))
    }};
}

macro_rules! decapsulate {
    ($curve:ident, $curve_name:ident, $sk:expr, $ct:expr) => {{
        let ct =
            $curve::PublicKey::from_encoded_point(&$curve::EncodedPoint::from_bytes($ct).unwrap())
                .unwrap();
        let sk = $curve::SecretKey::from_bytes($sk.into())?;
        let sk_scalar = NonZeroScalar::from(sk);
        let ct_affine: AffinePoint<$curve::$curve_name> = ct.into();
        Ok(
            $curve::elliptic_curve::ecdh::diffie_hellman(sk_scalar, ct_affine)
                .raw_secret_bytes()
                .to_vec(),
        )
    }};
}

macro_rules! key_gen {
    ($self:expr, $curve:ident) => {{
        let sk = $curve::SecretKey::random(&mut $self.rng);
        let pk = sk.public_key();
        (
            pk.to_encoded_point(true).as_bytes().to_vec(),
            sk.to_bytes().to_vec(),
        )
    }};
}

pub(crate) use decapsulate;
pub(crate) use encapsulate;
pub(crate) use key_gen;
