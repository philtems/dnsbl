use std::net::Ipv4Addr;

// Constantes DNS
pub const NS_RECORD_TTL: u32 = 86400;
pub const A_RECORD_TTL: u32 = 300;
pub const TXT_RECORD_TTL: u32 = 3600;
pub const MX_RECORD_TTL: u32 = 3600;
pub const DNS_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
pub const TEST_IP_PREFIX: [u8; 4] = [127, 0, 0, 2];
pub const TEST_IP_OCTETS: [u8; 4] = [2, 0, 0, 127];

#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub text: String,
}

impl TxtRecord {
    pub fn with_substitution(&self, ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        let dotted = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        let reversed = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
        
        self.text
            .replace("@dotted", &dotted)
            .replace("@reversed", &reversed)
            .replace("@", &dotted)
    }
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub server: String,
    pub priority: u16,
}

#[derive(Debug, Clone)]
pub struct DnsblServerInfo {
    pub name_servers: Vec<Ipv4Addr>,
    pub last_update: std::time::Instant,
    pub current_index: usize,
}

impl DnsblServerInfo {
    pub fn new() -> Self {
        DnsblServerInfo {
            name_servers: Vec::new(),
            last_update: std::time::Instant::now(),
            current_index: 0,
        }
    }

    pub fn needs_update(&self) -> bool {
        self.name_servers.is_empty() || self.last_update.elapsed() > std::time::Duration::from_secs(3600)
    }

    pub fn get_next_server(&mut self) -> Option<Ipv4Addr> {
        if self.name_servers.is_empty() {
            return None;
        }
        
        let server = self.name_servers[self.current_index];
        self.current_index = (self.current_index + 1) % self.name_servers.len();
        Some(server)
    }
}

