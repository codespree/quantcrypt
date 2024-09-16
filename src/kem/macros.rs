macro_rules! key_gen_ml {
    ($rng:expr, $curve:ident) => {{
        let (dk, ek) = $curve::generate(&mut $rng);
        (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
    }};
}

macro_rules! encapsulate_ml {
    ($self:expr, $curve:ident, $pk:expr) => {{
        let ek = get_encapsulation_key_obj::<$curve>($pk.to_vec())?;
        let (ct, ss) = ek.encapsulate(&mut $self.rng).unwrap();
        let ct = ct.as_slice().to_vec();
        let ss = ss.as_slice().to_vec();
        Ok((ct, ss))
    }};
}

#[cfg(test)]
macro_rules! test_kem {
    ($kem:expr) => {{
        let (pk, sk) = $kem.key_gen(None);
        let (ct, ss) = $kem.encaps(&pk).unwrap();
        let ss2 = $kem.decap(&sk, &ct).unwrap();
        assert_eq!(ss, ss2);

        // Should generate different keys
        let (pk2, sk2) = $kem.key_gen(None);
        assert_ne!(pk, pk2);
        assert_ne!(sk, sk2);

        // Should generate the same keys
        let seed = [0u8; 32];
        let (pk3, sk3) = $kem.key_gen(Some(&seed));
        let (pk4, sk4) = $kem.key_gen(Some(&seed));

        assert_eq!(pk3, pk4);
        assert_eq!(sk3, sk4);
    }};
}

pub(crate) use encapsulate_ml;
pub(crate) use key_gen_ml;
#[cfg(test)]
pub(crate) use test_kem;
