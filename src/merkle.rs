use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

#[derive(Debug)]
pub enum ProofError {
    NonExistingElement,
}

pub struct MerkleTree {
    tree: Vec<Vec<Hash>>,
}

fn concat_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash(value: &[u8]) -> Hash {
    Sha3_256::digest(value).into()
}

impl MerkleTree {
    pub fn new(data: &Vec<&[u8]>) -> MerkleTree {
        let mut merkle = MerkleTree { tree: Vec::new() };
        if data.is_empty() {
            return merkle;
        }

        // push hashes of the input
        let leafs: Vec<Hash> = data.iter().map(|value| hash(value)).collect();
        merkle.tree.push(leafs);

        while let Some(previous_level) = merkle.tree.last() {
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
            merkle.tree.push(new_level);
        }

        merkle
    }

    // if even index, should look for right siblign
    // if odd, look for left sibling
    pub fn generate_proof(&self, value: &[u8]) -> Result<Vec<Hash>, ProofError> {
        let mut actual_index = match self.search_index(value) {
            Some(i) => i,
            None => return Err(ProofError::NonExistingElement),
        };
        let mut proofs = Vec::new();
        for level in &self.tree {
            if level.len() == 1 {
                // root achieved
                break;
            }
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

        Ok(proofs)
    }

    fn search_index(&self, value: &[u8]) -> Option<usize> {
        let value_hash = hash(value);
        if let Some(leafs) = self.tree.first() {
            leafs.iter().position(|x| *x == value_hash)
        } else {
            None
        }
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
        assert_eq!(proof[0], leaf_hash[0]);
        assert_eq!(proof[1], first_level[1]);
        assert_eq!(proof.len(), 2);
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
        assert_eq!(proof[0], leaf_hash[3]);
        assert_eq!(proof[1], first_level[0]);
        assert_eq!(proof.len(), 2);
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
        assert_eq!(proof[0], leaf_hash[4]);
        assert_eq!(proof[1], first_level[2]);
        assert_eq!(proof[2], second_level[0]);
        assert_eq!(proof.len(), 3);
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
}
