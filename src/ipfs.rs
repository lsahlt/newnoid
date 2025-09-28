// src/ipfs.rs
use anyhow::Result;
use reqwest::Client;
use reqwest::multipart;

/// POST bytes to local IPFS node and return CID string
pub async fn add_bytes_to_ipfs(bytes: Vec<u8>) -> Result<String, anyhow::Error> {
    let client = Client::new();
    let part = multipart::Part::bytes(bytes).file_name("upload.bin");
    let form = multipart::Form::new().part("file", part);

    // expects ipfs daemon at http://127.0.0.1:5001
    let res = client.post("http://127.0.0.1:5001/api/v0/add")
        .multipart(form)
        .send()
        .await?;

    let text = res.text().await?;
    // The API returns lines like: {"Name":"upload.bin","Hash":"Qm...","Size":"123"}
    // We'll parse JSON to get the Hash/CID
    let json: serde_json::Value = serde_json::from_str(&text)?;
    if let Some(hash) = json.get("Hash").and_then(|v| v.as_str()) {
        Ok(hash.to_string())
    } else {
        Err(anyhow::anyhow!("unexpected ipfs response: {}", text))
    }
}
