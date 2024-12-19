use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

pub struct MerkleTree {
    tree: Vec<Vec<Hash>>,
}

fn concat_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash(value: &str) -> Hash {
    Sha3_256::digest(value).into()
}

impl MerkleTree {
    pub fn new(data: &Vec<&str>) -> MerkleTree {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_of_2_data_input() {
        let data: Vec<&str> = vec!["this", "is", "a", "merkleTree"];

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
        let data: Vec<&str> = vec!["this", "is", "a", "merkle", "tree"];
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
}
