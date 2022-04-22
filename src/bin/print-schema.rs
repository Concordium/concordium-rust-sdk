use concordium_rust_sdk::*;

fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(types::BlockSummary);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
    Ok(())
}
