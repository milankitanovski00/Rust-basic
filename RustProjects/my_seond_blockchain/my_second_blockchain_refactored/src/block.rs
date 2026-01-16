use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use hex::encode;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}

impl Block {
    pub fn new(
        id: u64,
        previous_hash: String,
        data: String,
        nonce: u64,

    ) -> Self {
        let mut block = Self {
            id,
            timestamp: Utc::now().timestamp(),
            previous_hash,
            data,
            nonce,
            hash: String::new(),
        };
        block.hash = block.calculate_hash();
        block
    }
    pub fn calculate_hash(&self) -> String {
        let json = serde_json::to_string(&self).expect("cannot serialize block to json");
        let mut hasher = Sha256::new();
        hasher.update(json);
        encode(hasher.finalize())
    }
}