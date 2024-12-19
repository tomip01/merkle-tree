use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&str> = vec!["this", "is", "a", "merkleTree"];
    let _merkle = MerkleTree::new(data);
    println!("hello world!");
}
