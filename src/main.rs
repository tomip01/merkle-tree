use merkle::MerkleTree;

mod merkle;

fn main() {
    let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
    let merkle = MerkleTree::new(&data);
    let proof = merkle.generate_proof(b"is").unwrap();
    let _hash = &proof[0].hash;
    let _branch_side = &proof[0].branch_side;
    println!("hello world!");
}
