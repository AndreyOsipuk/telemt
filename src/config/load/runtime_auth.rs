use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

use crate::crypto::sha256;
use crate::error::{ProxyError, Result};

const ACCESS_SECRET_BYTES: usize = 16;

/// Precomputed, immutable user authentication data used by handshake hot paths.
#[derive(Debug, Clone, Default)]
pub(crate) struct UserAuthSnapshot {
    entries: Vec<UserAuthEntry>,
    by_name: HashMap<String, u32>,
    sni_index: HashMap<u64, Vec<u32>>,
    sni_initial_index: HashMap<u8, Vec<u32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct UserAuthEntry {
    pub(crate) user: String,
    pub(crate) secret: [u8; ACCESS_SECRET_BYTES],
    /// Stable secret identity used by process-wide admission fencing.
    pub(crate) credential_id: [u8; 16],
}

impl UserAuthSnapshot {
    pub(super) fn from_users(users: &HashMap<String, String>) -> Result<Self> {
        let mut entries = Vec::with_capacity(users.len());
        let mut by_name = HashMap::with_capacity(users.len());
        let mut sni_index = HashMap::with_capacity(users.len());
        let mut sni_initial_index = HashMap::with_capacity(users.len());

        for (user, secret_hex) in users {
            let decoded = hex::decode(secret_hex).map_err(|_| ProxyError::InvalidSecret {
                user: user.clone(),
                reason: "Must be 32 hex characters".to_string(),
            })?;
            if decoded.len() != ACCESS_SECRET_BYTES {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }

            let user_id = u32::try_from(entries.len()).map_err(|_| {
                ProxyError::Config("Too many users for runtime auth snapshot".to_string())
            })?;

            let mut secret = [0u8; ACCESS_SECRET_BYTES];
            secret.copy_from_slice(&decoded);
            let digest = sha256(&secret);
            let mut credential_id = [0; 16];
            credential_id.copy_from_slice(&digest[..16]);
            entries.push(UserAuthEntry {
                user: user.clone(),
                secret,
                credential_id,
            });
            by_name.insert(user.clone(), user_id);
            sni_index
                .entry(Self::sni_lookup_hash(user))
                .or_insert_with(Vec::new)
                .push(user_id);
            if let Some(initial) = user
                .as_bytes()
                .first()
                .map(|byte| byte.to_ascii_lowercase())
            {
                sni_initial_index
                    .entry(initial)
                    .or_insert_with(Vec::new)
                    .push(user_id);
            }
        }

        Ok(Self {
            entries,
            by_name,
            sni_index,
            sni_initial_index,
        })
    }

    pub(crate) fn entries(&self) -> &[UserAuthEntry] {
        &self.entries
    }

    pub(crate) fn user_id_by_name(&self, user: &str) -> Option<u32> {
        self.by_name.get(user).copied()
    }

    pub(crate) fn entry_by_id(&self, user_id: u32) -> Option<&UserAuthEntry> {
        let idx = usize::try_from(user_id).ok()?;
        self.entries.get(idx)
    }

    pub(crate) fn credential_id_by_name(&self, user: &str) -> Option<[u8; 16]> {
        self.user_id_by_name(user)
            .and_then(|user_id| self.entry_by_id(user_id))
            .map(|entry| entry.credential_id)
    }

    pub(crate) fn sni_candidates(&self, sni: &str) -> Option<&[u32]> {
        self.sni_index
            .get(&Self::sni_lookup_hash(sni))
            .map(Vec::as_slice)
    }

    pub(crate) fn sni_initial_candidates(&self, sni: &str) -> Option<&[u32]> {
        let initial = sni
            .as_bytes()
            .first()
            .map(|byte| byte.to_ascii_lowercase())?;
        self.sni_initial_index.get(&initial).map(Vec::as_slice)
    }

    fn sni_lookup_hash(value: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        for byte in value.bytes() {
            hasher.write_u8(byte.to_ascii_lowercase());
        }
        hasher.finish()
    }
}
