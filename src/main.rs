use merkle::hash;
use merkle::MerkleTree;

mod merkle;

fn main() {
    // create a tree
    let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
    let mut merkle = MerkleTree::new(&data);

    // generate a proof
    let proof = merkle.generate_proof(b"is").unwrap();
    let hashes = &proof.hashes;
    let root = &proof.root;
    let index = proof.index;

    // verify is a valid proof
    let verified = merkle.verify(hashes, &hash(b"is"), root, index);
    println!("Can the proof be verified? {verified}");

    // add element to the tree
    merkle.add(b"last");
}
