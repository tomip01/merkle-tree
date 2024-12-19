use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&str> = vec!["this", "is", "a", "merkleTree"];
    let merkle = MerkleTree::new(&data);
    let _proof = merkle.generate_proof("is");
    println!("hello world!");
}
