// Interface and an in-memory for key-value database where the key is bytes and is intended to be hash.
// Used to store merkle tree nodes. The database stores all (internal and leaf) nodes of the tree as a map
// `root node hash -> array of children nodes` and each of the children nodes can themselves be roots of more children nodes.
// Since the height of the tree is fixed and same for all branches in the tree (its a sparse MT), you know when to stop
// looking for more children nodes. The way you get the node at a leaf index is first looking up the root in the database and
// picking the children node at the correct index (base 4 or base 8 depending on the tree) and then looking up that child node in
// the database and so on.

use crate::errors::{BulletproofError, BulletproofErrorKind};
use std::collections::HashMap;

pub trait HashDb<T: Clone> {
    fn insert(&mut self, hash: Vec<u8>, value: T);

    fn get(&self, hash: &[u8]) -> Result<T, BulletproofError>;
}

#[derive(Clone, Debug)]
pub struct InMemoryHashDb<T: Clone> {
    db: HashMap<Vec<u8>, T>,
}

impl<T: Clone> HashDb<T> for InMemoryHashDb<T> {
    fn insert(&mut self, hash: Vec<u8>, value: T) {
        self.db.insert(hash, value);
    }

    fn get(&self, hash: &[u8]) -> Result<T, BulletproofError> {
        match self.db.get(hash) {
            Some(val) => Ok(val.clone()),
            None => Err(BulletproofErrorKind::HashNotFoundInDB {
                hash: hash.to_vec(),
            }
            .into()),
        }
    }
}

impl<T: Clone> InMemoryHashDb<T> {
    pub fn new() -> Self {
        let db = HashMap::<Vec<u8>, T>::new();
        Self { db }
    }
}
