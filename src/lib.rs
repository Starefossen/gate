pub mod cert;
pub mod controller;
pub mod proxy;
pub mod sni;
pub mod upstream;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type Allowlist = Arc<RwLock<HashSet<String>>>;
