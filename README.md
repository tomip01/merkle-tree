# Merkle Tree 
An implementation of a merkle tree in rust with simple features

## Features
* Create a Merkle Tree out of an array
* Generate a proof that it contains an element
* Verify that a given hash is contain in it
* Can add elements once it's built

## Usage
**Clone**
```bash
git clone https://github.com/tomip01/merkle-tree.git && cd merkle-tree
```
**Run**
```bash
make run
```

## Example
```rust
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
let verified = merkle.verify(proof, &hash(b"is"));
```
