// Déclaration des modules
pub mod config;
pub mod dns;
pub mod zones;
pub mod logging;
pub mod security;
pub mod utils;

// Ré-exportation des types principaux pour faciliter l'utilisation
pub use config::{ZoneConfig, GlobalConfig};
pub use zones::zone::Zone;
pub use zones::source::SourceType;
pub use logging::query_logger::QueryLogger;
pub use logging::dbl_saver::DblSaver;
pub use security::access_control::AccessControl;
pub use dns::server::DNSBLServer;

