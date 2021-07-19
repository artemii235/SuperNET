use super::{DbIdentifier, DbInstance, DbNamespaceId, InitDbResult};
use crate::mm_ctx::MmArc;
use futures::lock::{MappedMutexGuard as AsyncMappedMutexGuard, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use primitives::hash::H160;

/// The mapped mutex guard.
/// This implements `Deref<Db>`.
pub type DbLocked<'a, Db> = AsyncMappedMutexGuard<'a, Option<Db>, Db>;

pub struct ConstructibleDb<Db> {
    /// It's better to use something like [`Constructible`], but it doesn't provide a method to get the inner value by the mutable reference.
    mutex: AsyncMutex<Option<Db>>,
    db_namespace: DbNamespaceId,
    wallet_rmd160: H160,
}

impl<Db: DbInstance> ConstructibleDb<Db> {
    pub fn from_ctx(ctx: &MmArc) -> Self {
        ConstructibleDb {
            mutex: AsyncMutex::new(None),
            db_namespace: ctx.db_namespace,
            wallet_rmd160: ctx.rmd160().clone(),
        }
    }

    /// Locks the given mutex and checks if the inner database is initialized already or not,
    /// initializes it if it's required, and returns the locked instance.
    pub async fn get_or_initialize(&self) -> InitDbResult<DbLocked<'_, Db>> {
        let mut locked_db = self.mutex.lock().await;
        // Db is initialized already
        if locked_db.is_some() {
            return Ok(unwrap_tx_history_db(locked_db));
        }

        let db_id = DbIdentifier::new::<Db>(self.db_namespace, self.wallet_rmd160.clone());

        let db = Db::init(db_id).await?;
        *locked_db = Some(db);
        Ok(unwrap_tx_history_db(locked_db))
    }
}

/// # Panics
///
/// This function will `panic!()` if the inner value of the `guard` is `None`.
fn unwrap_tx_history_db<Db>(guard: AsyncMutexGuard<'_, Option<Db>>) -> DbLocked<'_, Db> {
    AsyncMutexGuard::map(guard, |wrapped_db| {
        wrapped_db
            .as_mut()
            .expect("The locked 'Option<Db>' must contain a value")
    })
}
