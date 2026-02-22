use std::fs::File;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DblSaver {
    enabled: bool,
    file: Option<Arc<RwLock<File>>>,
    saved_ips: Arc<RwLock<HashSet<Ipv4Addr>>>,
}

impl DblSaver {
    pub fn new(filename: Option<String>) -> io::Result<Self> {
        match filename {
            Some(path) => {
                if let Some(parent) = Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let file = File::create(path)?;
                Ok(DblSaver {
                    enabled: true,
                    file: Some(Arc::new(RwLock::new(file))),
                    saved_ips: Arc::new(RwLock::new(HashSet::new())),
                })
            }
            None => Ok(DblSaver {
                enabled: false,
                file: None,
                saved_ips: Arc::new(RwLock::new(HashSet::new())),
            }),
        }
    }

    pub fn save_ip(&self, ip: Ipv4Addr) {
        if !self.enabled {
            return;
        }

        let mut saved = self.saved_ips.write().unwrap();
        if saved.insert(ip) {
            if let Some(file_lock) = &self.file {
                let line = format!("{}\n", ip);
                if let Ok(mut file) = file_lock.write() {
                    let _ = file.write_all(line.as_bytes());
                    let _ = file.flush();
                }
            }
        }
    }
}

