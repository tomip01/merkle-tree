use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
    let merkle = MerkleTree::new(&data);
    let proof = merkle.generate_proof(b"is").unwrap();
    let _hashes = &proof.hashes;
    let _root = &proof.root;
    let _index = &proof.index;
    println!("hello world!");
}
