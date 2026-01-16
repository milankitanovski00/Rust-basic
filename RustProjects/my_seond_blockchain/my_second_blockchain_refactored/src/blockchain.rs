use sha2::digest::generic_array;

use crate::block::Block;

pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub difficulty: usize,
}

impl Blockchain {
    pub fn new(difficulty: usize) -> Self {
        let mut bc = Self {
            blocks: Vec::new(),
            difficulty,
        };
        bc.mine_genesis_block();
        bc
    }

    fn mine_genesis_block(&mut self){
        let genesis_block = Block::new(0, String::from("genesis"), String::from("genesis"), 2836);
        self.blocks.push(genesis_block);
    }

    pub fn add_block(&mut self, data: String){
        let Some(last_block) = self.blocks.last() else {return; };
        let new_block = Block::new(last_block.id+1, last_block.hash.clone(), data, 0);
        self.blocks.push(new_block);
        println!("New block added: {:?}", self.blocks.last());
    }

    pub fn is_chain_valid(&self) -> bool{
        for i in 1..self.blocks.len(){
            let current = &self.blocks[i];
            let previous = &self.blocks[i-1];

            if current.hash != previous.previous_hash{
                return false;
            }

             if current.hash != current.calculate_hash(){
                return false;
            }
        }
        true
    }
}