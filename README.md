# Merkle Tree 
An implementation of a merkle tree in rust with simple features.

A Merkle tree is a binary tree used to efficiently verify data integrity. Each leaf node contains a hash of data, and each non-leaf node is a hash of its child nodes. The top hash, called the Merkle root, represents the entire tree. It allows fast and secure verification of large datasets by only checking a small subset of hashes.

See also, [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree)

## Features
* Create a Merkle Tree out of an array
* Generate a proof that it contains an element
* Verify that a given hash is contain in it
* Can add elements once it's built

## Installation
1. Clone the repository:
```bash
git clone https://github.com/tomip01/merkle-tree.git
```
2. Change to the directory:
```bash
cd merkle-tree
```
3. Build project:
```bash
make build
```
4. For release build:
```bash
make build-release
```

## Usage

This library can build the tree from a vector of arrays of bytes with arbitrary length. You can create a tree like this:

```rust
let data: Vec<&[u8]> = vec![b"data1", b"data2", b"data3"];
let mut merkle = MerkleTree::new(&data);
```

Also, you can add dynamically new elements to the tree:
```rust
merkle.add(b"this");
merkle.add(b"is");
merkle.add(b"a");
merkle.add(b"merkle");
merkle.add(b"tree");
```

It is possible to generate a proof for an element if present in the tree. It returns a `Result<Proof, MerkleError>` type with the proof if it is contained or an Error if it is not:
```rust
let proof = merkle.generate_proof(b"is").unwrap();
```

Lastly, you can verify for a given proof if the element is present in the tree like this:
```rust
let verified = merkle.verify(proof, &hash(b"is"));
```
