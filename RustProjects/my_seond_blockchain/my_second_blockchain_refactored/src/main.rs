mod blockchain;
mod block;
use crate::blockchain::Blockchain;
fn main() {
     println!("Creating a simple blockchain...");
    let mut blockchain = Blockchain::new(2);

    println!("Mining first user block...");
    blockchain.add_block(String::from("First block data"));

    println!("Mining second user block...");
    blockchain.add_block(String::from("Second block data"));

    println!("Blockchain valid: {}", blockchain.is_chain_valid());
    println!("Final Blockchain structure: {:#?}", blockchain.blocks);
}
