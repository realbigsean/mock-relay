use lru::LruCache;
use parking_lot::Mutex;
use types::{EthSpec, ExecutionBlockHash, ExecutionPayload};

pub const DEFAULT_PAYLOAD_CACHE_SIZE: usize = 10;

/// A cache mapping execution payloads by tree hash roots.
pub struct PayloadCache<T: EthSpec> {
    payloads: Mutex<LruCache<PayloadCacheId, ExecutionPayload<T>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PayloadCacheId(ExecutionBlockHash);

impl<T: EthSpec> Default for PayloadCache<T> {
    fn default() -> Self {
        PayloadCache {
            payloads: Mutex::new(LruCache::new(DEFAULT_PAYLOAD_CACHE_SIZE)),
        }
    }
}

impl<T: EthSpec> PayloadCache<T> {
    pub fn put(&self, payload: ExecutionPayload<T>) -> Option<ExecutionPayload<T>> {
        let root = payload.block_hash();
        self.payloads.lock().put(PayloadCacheId(root), payload)
    }

    pub fn pop(&self, root: &ExecutionBlockHash) -> Option<ExecutionPayload<T>> {
        self.payloads.lock().pop(&PayloadCacheId(*root))
    }
}
