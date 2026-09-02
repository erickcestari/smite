//! Enums whose serde variant tags are spelled out in the source.
//!
//! `#[derive(Serialize, Deserialize)]` tags each variant with its declaration
//! index, and `postcard` writes that index to the wire.  Inserting, reordering
//! or removing a variant then silently re-labels every later variant, so a
//! persisted corpus decodes as different operations.  [`stable_enum!`] takes
//! the tag from the source instead (`Variant(T) = 7`): declaration order is
//! free and only the number is frozen.
//!
//! Rules: never reuse a tag, even a retired one.  Duplicate tags fail to
//! compile via `unreachable_patterns`.
//!
//! Struct variants are encoded as a tuple of their fields.  That is
//! byte-identical to serde's struct-variant encoding under `postcard`, which
//! writes neither field names nor a length.

macro_rules! stable_enum {
    (
        $(#[$meta:meta])* $vis:vis enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident
                    $( ($ty:ty) )?
                    $( { $( $(#[$fmeta:meta])* $field:ident : $fty:ty ),* $(,)? } )?
                    = $tag:literal
            ),* $(,)?
        }
    ) => {
        $(#[$meta])* $vis enum $name {
            $( $(#[$vmeta])* $variant $( ($ty) )? $( { $( $(#[$fmeta])* $field: $fty ),* } )? ),*
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                match self {
                    $(
                        stable_enum!(@pat $name::$variant, payload $( ($ty) )? $( { $($field),* } )?) =>
                            stable_enum!(@ser s, $name, $variant, $tag, payload $( ($ty) )? $( { $($field),* } )?),
                    )*
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                const VARIANTS: &[&str] = &[$(stringify!($variant)),*];
                struct TagVisitor;
                impl<'de> ::serde::de::Visitor<'de> for TagVisitor {
                    type Value = $name;
                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str(stringify!($name))
                    }
                    #[deny(unreachable_patterns)]
                    fn visit_enum<A: ::serde::de::EnumAccess<'de>>(self, a: A) -> Result<$name, A::Error> {
                        let (tag, v) = a.variant::<u32>()?;
                        match tag {
                            $( $tag => stable_enum!(@de v, $name, $variant $( ($ty) )? $( { $($field: $fty),* } )?), )*
                            _ => Err(::serde::de::Error::unknown_variant(&tag.to_string(), VARIANTS)),
                        }
                    }
                }
                d.deserialize_enum(stringify!($name), VARIANTS, TagVisitor)
            }
        }
    };

    (@pat $n:ident::$v:ident, $p:ident) => { $n::$v };
    (@pat $n:ident::$v:ident, $p:ident ($ty:ty)) => { $n::$v($p) };
    (@pat $n:ident::$v:ident, $p:ident { $($f:ident),* }) => { $n::$v { $($f),* } };

    (@ser $s:ident, $n:ident, $v:ident, $t:literal, $p:ident) => {
        $s.serialize_unit_variant(stringify!($n), $t, stringify!($v))
    };
    (@ser $s:ident, $n:ident, $v:ident, $t:literal, $p:ident ($ty:ty)) => {
        $s.serialize_newtype_variant(stringify!($n), $t, stringify!($v), $p)
    };
    (@ser $s:ident, $n:ident, $v:ident, $t:literal, $p:ident { $($f:ident),* }) => {
        $s.serialize_newtype_variant(stringify!($n), $t, stringify!($v), &($($f,)*))
    };

    (@de $a:ident, $n:ident, $v:ident) => {
        ::serde::de::VariantAccess::unit_variant($a).map(|()| $n::$v)
    };
    (@de $a:ident, $n:ident, $v:ident ($ty:ty)) => {
        ::serde::de::VariantAccess::newtype_variant::<$ty>($a).map($n::$v)
    };
    (@de $a:ident, $n:ident, $v:ident { $($f:ident : $ft:ty),* }) => {
        ::serde::de::VariantAccess::newtype_variant::<($($ft,)*)>($a)
            .map(|($($f,)*)| $n::$v { $($f),* })
    };
}
pub(crate) use stable_enum;
