use merkle::hash;
use merkle::MerkleTree;

mod merkle;

fn main() {
    // create a tree
    let data: Vec<&[u8]> = vec![b"this"];
    let mut merkle = MerkleTree::new(&data);

    // add elements to the tree
    merkle.add(b"is");
    merkle.add(b"a");
    merkle.add(b"merkle");
    merkle.add(b"tree");

    // generate a proof
    let proof = merkle.generate_proof(b"is").unwrap();

    // verify is a valid proof
    let verified = merkle.verify(&proof, &hash(b"is"));
    println!("Can the proof be verified? {verified}");
}
