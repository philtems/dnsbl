#[derive(Debug, Clone)]
pub enum SourceType {
    Http(String),
    File(String),
    Dnsbl(String),
}

