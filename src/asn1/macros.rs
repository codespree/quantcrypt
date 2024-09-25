macro_rules! seq_next_element {
    ($seq:ident, $typ:ident, $missing_elem:literal) => {{
        const _: Option<$typ> = None;
        $seq.next_element()?.ok_or_else(|| {
            de::Error::invalid_value(
                serde::de::Unexpected::Other(concat!(
                    "[",
                    stringify!($typ),
                    "] ",
                    $missing_elem,
                    " is missing"
                )),
                &concat!("valid ", $missing_elem),
            )
        })?
    }};
    ($seq:ident, $typ_hint:path, $typ:ident, $missing_elem:literal) => {{
        const _: Option<$typ> = None;
        $seq.next_element::<$typ_hint>()?.ok_or_else(|| {
            de::Error::invalid_value(
                serde::de::Unexpected::Other(concat!(
                    "[",
                    stringify!($typ),
                    "] ",
                    $missing_elem,
                    " is missing"
                )),
                &concat!("valid ", $missing_elem),
            )
        })?
    }};
}

macro_rules! serde_invalid_value {
    ($typ:ident, $unexp:literal, $exp:literal) => {{
        const _: Option<$typ> = None;
        de::Error::invalid_value(
            serde::de::Unexpected::Other(concat!("[", stringify!($typ), "] ", $unexp)),
            &$exp,
        )
    }};
}

pub(crate) use seq_next_element;
pub(crate) use serde_invalid_value;
