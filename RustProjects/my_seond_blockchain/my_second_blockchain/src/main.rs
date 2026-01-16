use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use hex::encode;

// Define the structure of a Block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}

// Define the structure of the Blockchain
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub difficulty: usize,
}

// Implement methods for the Block struct
impl Block {
    // Calculate the block's hash
    pub fn calculate_hash(&self) -> String {
        let json = serde_json::to_string(&self).expect("Cannot serialize to json");
        let mut hasher = Sha256::new();
        hasher.update(json);
        encode(hasher.finalize())
    }
}

// Implement methods for the Blockchain struct
impl Blockchain {
    // Create a new Blockchain instance with a genesis block
    pub fn new(difficulty: usize) -> Self {
        let mut bc = Self { blocks: Vec::new(), difficulty };
        bc.mine_genesis_block();
        bc
    }

    // Create and add the first block (genesis block)
    fn mine_genesis_block(&mut self) {
        let genesis_block = Block {
            id:0,
            timestamp:Utc::now().timestamp(),
            previous_hash: String::from("genesis"),
            data: String::from("genesis"),
            nonce: 2836, // Hardcoded for simplicity in this example
            hash: "0000f816a87f806bb0073dcf026a64fb40c946b5abee2573702828694d5b4c43".to_string(),
        };
        self.blocks.push(genesis_block)
    }

    // Add a new block to the chain (simplified, without actual mining loop here)
    pub fn add_block(&mut self, data: String) {
        let Some(last_block) = self.blocks.last() else {return; };
        let mut new_block = Block {
            id: last_block.id + 1,
            timestamp: Utc::now().timestamp(),
            previous_hash: last_block.hash.clone(),
            data,
            nonce:0,    // In a real example, this is found via mining
            hash: String::new(),
        };
        // In a full implementation, the `mine()` function would be called here to find a valid nonce and hash
        new_block.hash = new_block.calculate_hash();
        self.blocks.push(new_block);
        println!("New block added: {:?}", self.blocks.last());
    }

    // Function to check if the chain is valid
    pub fn is_chain_valid(&self) -> bool {
        for i in 1..self.blocks.len() {
            let current_block = &self.blocks[i];
            let previous_block = &self.blocks[i - 1];

            if current_block.previous_hash != previous_block.hash {
                return false; // Link between blocks is broken
            }
            // Add more validation rules here (e.g., hash complexity)
        }
        true
    }

}

fn main() {
    println!("Creating a simple blockchain...");
    let mut blockchain = Blockchain::new(2); // Difficulty of 2 (leading zeros)

    println!("Mining first user block...");
    blockchain.add_block(String::from("First block data"));

    println!("Mining second user block...");
    blockchain.add_block(String::from("Second block data"));

    println!("Blockchain valid: {}", blockchain.is_chain_valid());
    println!("Final Blockchain structure: {:#?}", blockchain.blocks);
}
