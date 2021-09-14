pub(crate) mod timestamp_millis {
    use serde::Deserialize;
    /// Serialize (via Serde) chrono::DateTime in milliseconds as an u64.
    pub fn serialize<S: serde::Serializer>(
        dt: &chrono::DateTime<chrono::Utc>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_i64(dt.timestamp_millis())
    }

    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        des: D,
    ) -> Result<chrono::DateTime<chrono::Utc>, D::Error> {
        let millis = i64::deserialize(des)?;
        Ok(chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH)
            + chrono::Duration::milliseconds(millis))
    }
}

pub(crate) mod byte_array_hex {
    /// Serialize (via Serde) chrono::DateTime in milliseconds as an u64.
    pub fn serialize<S: serde::Serializer>(dt: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(hex::encode(dt).as_str())
    }

    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(des: D) -> Result<Vec<u8>, D::Error> {
        struct HexVisitor;
        impl<'de> serde::de::Visitor<'de> for HexVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "A hex string.")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error, {
                let r = hex::decode(v).map_err(serde::de::Error::custom)?;
                Ok(r)
            }
        }
        des.deserialize_str(HexVisitor)
    }
}

/// Serialize amounts as u64
pub(crate) mod amounts_as_u64 {
    use crypto_common::types::Amount;
    use serde::Serialize;
    /// Serialize an Amount as usual. See deserialize below for why we include
    /// this at all.
    #[inline(always)]
    pub fn serialize<S: serde::Serializer>(amnt: &Amount, ser: S) -> Result<S::Ok, S::Error> {
        amnt.serialize(ser)
    }

    /// Deserialize an Amount either from an integer in microGTU expressed as a
    /// u64 or from its own parser (from string)
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(des: D) -> Result<Amount, D::Error> {
        struct AmountVisitor;
        impl<'de> serde::de::Visitor<'de> for AmountVisitor {
            type Value = Amount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "A non-negative integer or a string containing an integer."
                )
            }

            fn visit_u64<E: serde::de::Error>(self, microgtu: u64) -> Result<Self::Value, E> {
                Ok(Amount { microgtu })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let microgtu = v.parse::<u64>().map_err(|_| {
                    E::custom(
                        "Invalid amount value. Expecting a string containing a non-negative \
                         integer < 2^64.",
                    )
                })?;
                Ok(Amount { microgtu })
            }
        }
        des.deserialize_any(AmountVisitor)
    }
}

pub(crate) mod account_amounts {
    use crypto_common::{types::Amount, SerdeDeserialize, SerdeSerialize};
    use id::types::AccountAddress;
    use serde::de::Error;
    use std::collections::BTreeMap;

    #[derive(SerdeSerialize, SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    struct AccountAmount {
        address: AccountAddress,
        amount:  Amount,
    }
    pub fn serialize<S: serde::Serializer>(
        dt: &BTreeMap<AccountAddress, Amount>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.collect_seq(
            dt.iter()
                .map(|(&address, &amount)| AccountAmount { address, amount }),
        )
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        des: D,
    ) -> Result<BTreeMap<AccountAddress, Amount>, D::Error> {
        struct AccountAmountsVisitor;
        impl<'de> serde::de::Visitor<'de> for AccountAmountsVisitor {
            type Value = BTreeMap<AccountAddress, Amount>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "A list of objects with fields 'address' and 'amount'."
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>, {
                let mut out = BTreeMap::new();
                while let Some(e) = seq.next_element::<AccountAmount>()? {
                    if out.insert(e.address, e.amount).is_some() {
                        return Err(A::Error::custom(
                            "Duplicate element encountered when reading AccountAmounts.",
                        ));
                    }
                }
                Ok(out)
            }
        }
        des.deserialize_seq(AccountAmountsVisitor)
    }
}

/// Module to help checking that a value is not default during serialization.
/// This is particularly interesting for various integer types, where the
/// default value is 0.
pub(crate) mod deserialize_non_default {
    use crypto_common::SerdeDeserialize;

    pub fn deserialize<'de, D, A>(des: D) -> Result<A, D::Error>
    where
        D: serde::Deserializer<'de>,
        A: SerdeDeserialize<'de> + Default + PartialEq + Eq, {
        let s = A::deserialize(des)?;
        if s == A::default() {
            return Err(serde::de::Error::custom("Expected a non-default value."));
        }
        Ok(s)
    }
}

pub(crate) mod duration_millis {
    use serde::Deserialize;
    /// Serialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn serialize<S: serde::Serializer>(
        duration: &chrono::Duration,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_i64(duration.num_milliseconds())
    }

    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        des: D,
    ) -> Result<chrono::Duration, D::Error> {
        let millis = i64::deserialize(des)?;
        Ok(chrono::Duration::milliseconds(millis))
    }
}
