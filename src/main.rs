use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
    let merkle = MerkleTree::new(&data);
    let _proof = merkle.generate_proof(b"is");
    println!("hello world!");
}
