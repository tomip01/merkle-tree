use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

/// enum for errors related to the Merkle Tree
/// NonExistingElement is for when generating a proof for an element it's not contained in the tree
#[derive(Debug)]
pub enum MerkleError {
    NonExistingElement,
}

/// The Merkle Tree
/// Contains the tree itself as a vector of vector of hashes
/// It is built from the bottom to the root, first vector is the leaves, the last the root
pub struct MerkleTree {
    tree: Vec<Vec<Hash>>,
}

/// Result type when generating proofs
/// hashes: contain the hashes necessary to verify the proof
/// index: is the index of the element in the leaf level
/// root: root of the tree
pub struct Proof {
    pub hashes: Vec<Hash>,
    pub index: usize,
    pub root: Hash,
}

/// given two references of hashes, concatenates them and hashes
pub fn concat_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// hashes an array of bytes
pub fn hash(value: &[u8]) -> Hash {
    Sha3_256::digest(value).into()
}

impl MerkleTree {
    /// data: a vector of an array of bytes to build the tree. Each element of the vector is a leaf to hash
    pub fn new(data: &Vec<&[u8]>) -> MerkleTree {
        let mut merkle = MerkleTree { tree: Vec::new() };
        if data.is_empty() {
            return merkle;
        }
        // push hashes of the input
        let leaves: Vec<Hash> = data.iter().map(|value| hash(value)).collect();

        merkle.tree.push(leaves);
        merkle.build();
        merkle
    }

    /// private function to build a tree bottom up from the leaves
    fn build(&mut self) {
        while let Some(previous_level) = self.tree.last() {
            if previous_level.len() == 1 {
                // root achieved
                break;
            }
            let mut new_level: Vec<Hash> = Vec::new();
            for (i, hash_i) in previous_level.iter().enumerate() {
                // take hashes by two => take by even indexes
                if i % 2 != 0 {
                    continue;
                }

                let sibling_hash = match previous_level.get(i + 1) {
                    Some(existing_hash) => existing_hash,
                    None => hash_i, // if no sibling, use the same hash to concatenate
                };
                let concatenated_hash: Hash = concat_hash(hash_i, sibling_hash);
                new_level.push(concatenated_hash);
            }
            self.tree.push(new_level);
        }
    }

    /// value: elemento to search if it is in a leaf
    /// then return only necesary hashes to calculate the root
    /// Returns the Proof or an Error
    pub fn generate_proof(&self, value: &[u8]) -> Result<Proof, MerkleError> {
        let element_index = match self.search_index(value) {
            Some(i) => i,
            None => return Err(MerkleError::NonExistingElement),
        };
        let mut actual_index = element_index;
        let mut proofs = Vec::new();
        for level in &self.tree {
            if level.len() == 1 {
                // root achieved
                break;
            }
            // if even index, should look for right siblign
            // if odd, look for left sibling
            let sibling_index = if actual_index % 2 == 0 {
                actual_index + 1
            } else {
                actual_index - 1
            };

            match level.get(sibling_index) {
                Some(hash) => proofs.push(*hash),
                None => proofs.push(*level.get(actual_index).unwrap()),
            };

            // the reason for actual_index is divided by two is because in the parent level
            // it has a half of hashes. Then when divided by two it gets the floor of the division
            // reaching the correct index
            actual_index /= 2;
        }

        Ok(Proof {
            hashes: proofs,
            index: element_index,
            root: *self.get_root().unwrap(),
        })
    }

    /// given a value, looks for and index in the leaf vector of the tree. Returns its index
    fn search_index(&self, value: &[u8]) -> Option<usize> {
        let value_hash = hash(value);
        // the first element of the tree are the leaves
        // then if not empty tree, search the position of the value hashed
        if let Some(leaves) = self.tree.first() {
            leaves.iter().position(|x| *x == value_hash)
        } else {
            None
        }
    }

    fn get_root(&self) -> Option<&Hash> {
        if let Some(root_level) = self.tree.last() {
            root_level.first()
        } else {
            None
        }
    }

    /// Verify if the leaf with a given proof and index can calculate the same root as provided
    pub fn verify(&self, proof: &Vec<Hash>, leaf: &Hash, root: &Hash, index: usize) -> bool {
        let mut actual_index = index;
        let mut actual_hash = *leaf;

        // same logic as `generate_proof`
        for proof_hash in proof {
            actual_hash = match actual_index % 2 == 0 {
                true => concat_hash(&actual_hash, proof_hash),
                false => concat_hash(proof_hash, &actual_hash),
            };
            actual_index /= 2;
        }
        &actual_hash == root
    }

    /// value: new element to be added to the tree. It has to be an array of bytes
    pub fn add(&mut self, value: &[u8]) {
        let new_leaf = hash(value);
        let leaves = self.get_mut_leaves();
        leaves.push(new_leaf);

        // tree with only one element, the root
        if leaves.len() == 1 {
            return;
        }

        let mut actual_index = leaves.len() - 1;

        // iterate once per level in the tree to create or update the hashes
        for i in 0..self.tree.len() - 1 {
            let current_level = &self.tree[i];

            // determine which side to look for the hash
            let sibling_index = if actual_index % 2 == 0 {
                actual_index + 1
            } else {
                actual_index - 1
            };

            let self_hash = current_level.get(actual_index).unwrap();
            let sibling_hash = match current_level.get(sibling_index) {
                Some(hash) => hash,
                None => current_level.get(actual_index).unwrap(),
            };

            let new_hash = if actual_index % 2 == 0 {
                concat_hash(self_hash, sibling_hash)
            } else {
                concat_hash(sibling_hash, self_hash)
            };

            actual_index /= 2;

            // now check if element is present, then update the hash (only occur when the same hash is used to create a new one)
            // if not present, push the new hash
            match self.tree[i + 1].get(actual_index) {
                Some(_) => self.tree[i + 1][actual_index] = new_hash,
                None => self.tree[i + 1].push(new_hash),
            }
        }

        // this is for when the tree raise one level. The previous root level now has two elements instead of one
        // then we need to create a new level with the hash of the two elements concatenated
        if let Some(last_level) = self.tree.last() {
            if last_level.len() == 2 {
                self.tree
                    .push(vec![concat_hash(&last_level[0], &last_level[1])]);
            }
        }
    }

    fn get_mut_leaves(&mut self) -> &mut Vec<Hash> {
        if self.tree.first_mut().is_none() {
            let leaves = vec![];
            self.tree.push(leaves);
        }
        // I ensured it's not empty
        self.tree.first_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_of_2_data_input() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];

        // calculate hashes with the library
        let leaf_hash = vec![hash(data[0]), hash(data[1]), hash(data[2]), hash(data[3])];
        let first_level = vec![
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
        ];
        let root = vec![concat_hash(&first_level[0], &first_level[1])];

        let merkle = MerkleTree::new(&data);

        // compare merkle tree has the same hashes an lengthes
        assert_eq!(leaf_hash, merkle.tree[0]);
        assert_eq!(first_level, merkle.tree[1]);
        assert_eq!(root, merkle.tree[2]);
    }

    #[test]
    fn not_power_of_2_data_input() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
        let leaf_hash = vec![
            hash(data[0]),
            hash(data[1]),
            hash(data[2]),
            hash(data[3]),
            hash(data[4]),
        ];
        let first_level = vec![
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
            concat_hash(&leaf_hash[4], &leaf_hash[4]),
        ];
        let second_level = vec![
            concat_hash(&first_level[0], &first_level[1]),
            concat_hash(&first_level[2], &first_level[2]),
        ];
        let root = vec![concat_hash(&second_level[0], &second_level[1])];

        let merkle = MerkleTree::new(&data);

        assert_eq!(leaf_hash, merkle.tree[0]);
        assert_eq!(first_level, merkle.tree[1]);
        assert_eq!(second_level, merkle.tree[2]);
        assert_eq!(root, merkle.tree[3]);
    }

    #[test]
    fn generate_proof_easy_path() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];

        // calculate hashes with the library
        let leaf_hash = [hash(data[0]), hash(data[1]), hash(data[2]), hash(data[3])];
        let first_level = [
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
        ];

        let merkle = MerkleTree::new(&data);

        let proof = merkle.generate_proof(b"is").unwrap();
        assert_eq!(proof.hashes[0], leaf_hash[0]);
        assert_eq!(proof.hashes[1], first_level[1]);
        assert_eq!(proof.hashes.len(), 2);
        assert_eq!(proof.root, merkle.tree.last().unwrap()[0]);
        assert_eq!(proof.index, 1);
    }

    #[test]
    fn generate_proof_easy_path_start_on_right() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];

        // calculate hashes with the library
        let leaf_hash = [hash(data[0]), hash(data[1]), hash(data[2]), hash(data[3])];
        let first_level = [
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
        ];

        let merkle = MerkleTree::new(&data);

        let proof = merkle.generate_proof(b"a").unwrap();
        assert_eq!(proof.hashes[0], leaf_hash[3]);
        assert_eq!(proof.hashes[1], first_level[0]);
        assert_eq!(proof.hashes.len(), 2);
        assert_eq!(proof.root, merkle.tree.last().unwrap()[0]);
        assert_eq!(proof.index, 2);
    }

    #[test]
    fn generate_proof_on_five_entries() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
        let leaf_hash = [
            hash(data[0]),
            hash(data[1]),
            hash(data[2]),
            hash(data[3]),
            hash(data[4]),
        ];
        let first_level = [
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
            concat_hash(&leaf_hash[4], &leaf_hash[4]),
        ];
        let second_level = [
            concat_hash(&first_level[0], &first_level[1]),
            concat_hash(&first_level[2], &first_level[2]),
        ];

        let merkle = MerkleTree::new(&data);

        let proof = merkle.generate_proof(b"tree").unwrap();
        assert_eq!(proof.hashes[0], leaf_hash[4]);
        assert_eq!(proof.hashes[1], first_level[2]);
        assert_eq!(proof.hashes[2], second_level[0]);
        assert_eq!(proof.hashes.len(), 3);
        assert_eq!(proof.root, merkle.tree.last().unwrap()[0]);
        assert_eq!(proof.index, 4);
    }

    #[test]
    fn error_proof_on_notexisting_element() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
        let merkle = MerkleTree::new(&data);
        assert!(merkle.generate_proof(b"non_existing").is_err());
    }

    #[test]
    fn error_proof_on_empty_tree() {
        let data: Vec<&[u8]> = vec![];
        let merkle = MerkleTree::new(&data);
        assert!(merkle.generate_proof(b"non_existing").is_err());
    }

    #[test]
    fn happy_verify() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];
        let merkle = MerkleTree::new(&data);
        let proof = merkle.generate_proof(b"is").unwrap();
        assert!(merkle.verify(&proof.hashes, &hash(b"is"), &proof.root, proof.index));
    }

    #[test]
    fn bad_verify_different_proof_for_element() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];
        let merkle = MerkleTree::new(&data);
        let proof = merkle.generate_proof(b"is").unwrap();
        assert!(!merkle.verify(&proof.hashes, &hash(b"a"), &proof.root, proof.index));
    }

    #[test]
    fn bad_verify_wrong_root() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];
        let merkle = MerkleTree::new(&data);
        let proof = merkle.generate_proof(b"is").unwrap();
        let bad_root = [0_u8; 32];
        assert!(!merkle.verify(&proof.hashes, &hash(b"a"), &bad_root, proof.index));
    }

    #[test]
    fn add_correct_for_three_elements() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a"];

        let mut merkle = MerkleTree::new(&data);
        merkle.add(b"merkleTree");

        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkleTree"];

        // calculate hashes with the library
        let leaf_hash = vec![hash(data[0]), hash(data[1]), hash(data[2]), hash(data[3])];
        let first_level = vec![
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
        ];
        let root = vec![concat_hash(&first_level[0], &first_level[1])];

        assert_eq!(leaf_hash, merkle.tree[0]);
        assert_eq!(first_level, merkle.tree[1]);
        assert_eq!(root, merkle.tree[2]);
        assert_eq!(3, merkle.tree.len());
    }

    #[test]
    fn add_correct_for_four_elements() {
        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle"];

        let mut merkle = MerkleTree::new(&data);
        merkle.add(b"tree");

        let data: Vec<&[u8]> = vec![b"this", b"is", b"a", b"merkle", b"tree"];
        let leaf_hash = vec![
            hash(data[0]),
            hash(data[1]),
            hash(data[2]),
            hash(data[3]),
            hash(data[4]),
        ];
        let first_level = vec![
            concat_hash(&leaf_hash[0], &leaf_hash[1]),
            concat_hash(&leaf_hash[2], &leaf_hash[3]),
            concat_hash(&leaf_hash[4], &leaf_hash[4]),
        ];
        let second_level = vec![
            concat_hash(&first_level[0], &first_level[1]),
            concat_hash(&first_level[2], &first_level[2]),
        ];
        let root = vec![concat_hash(&second_level[0], &second_level[1])];

        assert_eq!(leaf_hash, merkle.tree[0]);
        assert_eq!(first_level, merkle.tree[1]);
        assert_eq!(second_level, merkle.tree[2]);
        assert_eq!(root, merkle.tree[3]);
        assert_eq!(4, merkle.tree.len());
    }
}
