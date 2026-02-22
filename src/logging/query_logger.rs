use std::fs::File;
use std::io::{self, Write};
use std::net::{SocketAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct QueryLogger {
    enabled: bool,
    file: Option<Arc<RwLock<File>>>,
}

impl QueryLogger {
    pub fn new(filename: Option<String>) -> io::Result<Self> {
        match filename {
            Some(path) => {
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let file = File::create(path)?;
                Ok(QueryLogger {
                    enabled: true,
                    file: Some(Arc::new(RwLock::new(file))),
                })
            }
            None => Ok(QueryLogger {
                enabled: false,
                file: None,
            }),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_query(&self, src: SocketAddr, domain: &str, qtype: u16, 
                     response_code: u8, response_ip: Option<Ipv4Addr>, 
                     response_txt: Option<&str>, source: Option<&str>,
                     action: Option<&str>) {
        if !self.enabled {
            return;
        }

        if let Some(file_lock) = &self.file {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let qtype_str = match qtype {
                1 => "A",
                2 => "NS",
                5 => "CNAME",
                6 => "SOA",
                12 => "PTR",
                15 => "MX",
                16 => "TXT",
                28 => "AAAA",
                48 => "DNSKEY",
                255 => "ANY",
                _ => "UNKNOWN",
            };
            
            let status = if let Some(action) = action {
                format!("ACTION:{}", action)
            } else if response_code == 0 {
                match qtype {
                    1 => format!("A_RESPONSE {}", response_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    2 => "NS_RESPONSE".to_string(),
                    6 => "SOA_RESPONSE".to_string(),
                    15 => format!("MX_RESPONSE {}", response_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
                    16 => format!("TXT_RESPONSE \"{}\"", response_txt.unwrap_or("")),
                    _ => "RESPONSE".to_string(),
                }
            } else {
                match response_code {
                    3 => "NXDOMAIN".to_string(),
                    4 => "NOTIMP".to_string(),
                    5 => "REFUSED".to_string(),
                    _ => format!("ERROR_{}", response_code),
                }
            };
            
            let source_info = match source {
                Some(s) => format!(" [source:{}]", s),
                None => "".to_string(),
            };
            
            let log_line = format!("[{}] {} {} {} {}{}\n", 
                timestamp, src.ip(), domain, qtype_str, status, source_info);
            
            if let Ok(mut file) = file_lock.write() {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            }
        }
    }
}

