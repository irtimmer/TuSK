use std::collections::HashMap;

use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::CtapResult;

pub struct TuskPersist {
    data: HashMap<usize, Vec<u8>>,
}

impl TuskPersist {
    pub fn new() -> Self {
        TuskPersist {
            data: HashMap::new(),
        }
    }
}

impl Persist for TuskPersist {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        Ok(self.data.get(&key).cloned())
    }

    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        self.data.insert(key, value.to_vec());
        Ok(())
    }

    fn remove(&mut self, key: usize) -> CtapResult<()> {
        self.data.remove(&key);
        Ok(())
    }

    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        let iter = self.data.keys().into_iter().map(|k| Ok(k.clone()));
        Ok(Box::new(iter))
    }
}
