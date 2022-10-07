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

pub(crate) mod account_amounts {
    use concordium_base::{
        common::{types::Amount, SerdeDeserialize, SerdeSerialize},
        id::types::AccountAddress,
    };
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
