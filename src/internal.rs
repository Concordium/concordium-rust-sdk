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
    use crypto_common::{types::Amount, SerdeDeserialize, SerdeSerialize};
    use id::types::AccountAddress;
    use serde::de::Error;
    use std::collections::BTreeMap;

    #[derive(SerdeSerialize, SerdeDeserialize, schemars::JsonSchema)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct AccountAmount {
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

pub(crate) struct HexSchema;

impl schemars::JsonSchema for HexSchema {
    fn schema_name() -> String { "Hex string".into() }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::*;
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(
                StringValidation {
                    max_length: None,
                    min_length: Some(0),
                    pattern:    Some("^([0-9]?[a-f]?)*$".into()),
                }
                .into(),
            ),
            ..SchemaObject::default()
        })
    }
}
