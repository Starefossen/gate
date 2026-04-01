pub mod controller;
pub mod proxy;
pub mod sni;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type Allowlist = Arc<RwLock<HashSet<String>>>;
