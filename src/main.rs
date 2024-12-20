use merkle::hash;
use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
    let mut merkle = MerkleTree::new(&data);
    let proof = merkle.generate_proof(b"is").unwrap();
    let hashes = &proof.hashes;
    let root = &proof.root;
    let index = proof.index;
    let _verified = merkle.verify(hashes, &hash(b"is"), root, index);
    merkle.add(b"last");

    println!("hello world!");
}
