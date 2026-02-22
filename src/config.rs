use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use clap::{App, Arg};
use ipnetwork::IpNetwork;
use log::{info, warn};

use crate::dns::types::{TxtRecord, MxRecord};
use crate::security::access_control::AccessControl;
use crate::utils;


#[derive(Debug, Clone)]
pub struct ZoneConfig {
    pub domain: String,
    pub response_ip: Ipv4Addr,
    pub self_ip: Ipv4Addr,
    pub txt_records: Vec<TxtRecord>,
    pub mx_records: Vec<MxRecord>,
    pub sources: Vec<String>,
    pub source_files: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GlobalConfig {
    pub interface: Option<String>,
    pub max_requests: Option<usize>,
    pub no_request_limit: Option<String>,
    pub no_request_limit_file: Option<String>,
    pub deny_file: Option<String>,
    pub stats_interval: Option<u64>,
    pub query_log: Option<String>,
    pub dbl_save: Option<String>,
    pub reload: Option<u64>,
    pub daemon: Option<bool>,
    pub verbose: Option<bool>,
    pub log: Option<String>,
}

pub fn setup_logging(log_file: Option<&str>, verbose: bool) -> Result<(), fern::InitError> {
    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        });
    
    if let Some(log_file) = log_file {
        if let Some(parent) = Path::new(log_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        dispatch = dispatch.chain(fern::log_file(log_file)?);
    }
    
    dispatch = dispatch.chain(std::io::stdout());
    dispatch.apply()?;
    Ok(())
}

pub fn read_source_file(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut sources = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?.trim().to_string();
        if !line.is_empty() && !line.starts_with('#') {
            if line.starts_with("http://") || line.starts_with("https://") || 
               line.starts_with("dnsbl://") || Path::new(&line).exists() {
                sources.push(line);
            } else {
                warn!("Invalid source at line {}: {} (ignored)", line_num + 1, line);
            }
        }
    }
    
    Ok(sources)
}

pub fn read_ip_list_file(filename: &str) -> io::Result<Vec<IpNetwork>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut ips = Vec::new();
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        match utils::parse_ip_or_cidr(&line) {
            Ok(network) => ips.push(network),
            Err(e) => {
                warn!("Invalid IP or CIDR range at line {}: {} ({})", line_num + 1, line, e);
            }
        }
    }
    
    Ok(ips)
}

// Fonction simple pour parser un fichier INI sans dépendre des types
pub fn parse_ini_file(filename: &str) -> Result<HashMap<String, HashMap<String, String>>, String> {
    let mut content = String::new();
    File::open(filename)
        .map_err(|e| format!("Failed to open config file: {}", e))?
        .read_to_string(&mut content)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    
    let mut result = HashMap::new();
    let mut current_section = String::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        
        if line.starts_with('[') && line.ends_with(']') {
            // Nouvelle section
            current_section = line[1..line.len()-1].trim().to_string();
            result.entry(current_section.clone()).or_insert_with(HashMap::new);
        } else if !current_section.is_empty() {
            // Clé=valeur
            if let Some(equal_pos) = line.find('=') {
                let key = line[..equal_pos].trim().to_string();
                let value = line[equal_pos+1..].trim().to_string();
                if let Some(section_map) = result.get_mut(&current_section) {
                    section_map.insert(key, value);
                }
            }
        }
    }
    
    Ok(result)
}

pub fn parse_config_file(filename: &str) -> Result<(GlobalConfig, Vec<ZoneConfig>), String> {
    let sections = parse_ini_file(filename)?;
    
    let mut global = GlobalConfig::default();
    let mut zones = Vec::new();
    
    // Parser la section [global]
    if let Some(global_section) = sections.get("global") {
        for (key, value) in global_section {
            match key.as_str() {
                "interface" => global.interface = Some(value.clone()),
                "max-requests" => {
                    global.max_requests = Some(value.parse::<usize>()
                        .map_err(|_| format!("Invalid max-requests value: {}", value))?);
                }
                "no-request-limit" => global.no_request_limit = Some(value.clone()),
                "no-request-limit-file" => global.no_request_limit_file = Some(value.clone()),
                "deny-file" => global.deny_file = Some(value.clone()),
                "stats-interval" => {
                    global.stats_interval = Some(value.parse::<u64>()
                        .map_err(|_| format!("Invalid stats-interval value: {}", value))?);
                }
                "query-log" => global.query_log = Some(value.clone()),
                "dbl-save" => global.dbl_save = Some(value.clone()),
                "reload" => {
                    global.reload = Some(value.parse::<u64>()
                        .map_err(|_| format!("Invalid reload value: {}", value))?);
                }
                "daemon" => {
                    global.daemon = Some(value.parse::<bool>()
                        .map_err(|_| format!("Invalid daemon value (true/false): {}", value))?);
                }
                "verbose" => {
                    global.verbose = Some(value.parse::<bool>()
                        .map_err(|_| format!("Invalid verbose value (true/false): {}", value))?);
                }
                "log" => global.log = Some(value.clone()),
                _ => warn!("Unknown global option: {}", key),
            }
        }
    }
    
    // Parser les sections [domain "..."]
    for (section_name, props) in sections {
        if section_name.starts_with("domain ") {
            // Extraire le nom du domaine entre guillemets
            let domain = section_name.trim_start_matches("domain ").trim();
            let domain = domain.trim_matches('"').to_string();
            
            if domain.is_empty() {
                return Err(format!("Empty domain name in section [{}]", section_name));
            }
            
            let mut zone = ZoneConfig {
                domain,
                response_ip: Ipv4Addr::new(127, 0, 0, 2), // Default
                self_ip: Ipv4Addr::new(127, 0, 0, 2),    // Default
                txt_records: Vec::new(),
                mx_records: Vec::new(),
                sources: Vec::new(),
                source_files: Vec::new(),
            };
            
            for (key, value) in props {
                match key.as_str() {
                    "response" => {
                        zone.response_ip = Ipv4Addr::from_str(&value)
                            .map_err(|_| format!("Invalid response IP for {}: {}", zone.domain, value))?;
                    }
                    "self" => {
                        zone.self_ip = Ipv4Addr::from_str(&value)
                            .map_err(|_| format!("Invalid self IP for {}: {}", zone.domain, value))?;
                    }
                    "txt" => {
                        zone.txt_records.push(TxtRecord {
                            text: value.clone(),
                        });
                    }
                    "mx" => {
                        let parts: Vec<&str> = value.split(',').collect();
                        if parts.len() == 2 {
                            if let Ok(priority) = parts[1].parse::<u16>() {
                                zone.mx_records.push(MxRecord {
                                    server: parts[0].to_string(),
                                    priority,
                                });
                            } else {
                                warn!("Invalid MX priority for {}: {}", zone.domain, value);
                            }
                        } else {
                            warn!("Invalid MX format for {}: {} (expected server,priority)", 
                                  zone.domain, value);
                        }
                    }
                    "source" => {
                        zone.sources.push(value.clone());
                    }
                    "source-file" => {
                        zone.source_files.push(value.clone());
                    }
                    _ => warn!("Unknown option '{}' in section [{}]", key, section_name),
                }
            }
            
            zones.push(zone);
        }
    }
    
    Ok((global, zones))
}

pub fn merge_configs(cli_matches: &clap::ArgMatches, file_config: GlobalConfig) -> 
    (String, bool, bool, Option<String>, u64, AccessControl, Option<String>, Option<String>) {
    
    // Interface
    let interface = cli_matches.value_of("interface")
        .map(String::from)
        .or(file_config.interface)
        .unwrap_or_else(|| "0.0.0.0:53".to_string());
    
    // Verbose
    let verbose = if cli_matches.is_present("verbose") {
        true
    } else {
        file_config.verbose.unwrap_or(false)
    };
    
    // Daemon - si --no-daemon est présent, ça override tout
    let no_daemon = cli_matches.is_present("no-daemon");
    let daemon = if no_daemon {
        false
    } else if cli_matches.is_present("daemon") {
        true
    } else {
        file_config.daemon.unwrap_or(false)
    };
    
    // Log file
    let log_file = cli_matches.value_of("log")
        .map(String::from)
        .or(file_config.log);
    
    // Reload interval
    let reload = cli_matches.value_of("reload")
        .and_then(|v| v.parse::<u64>().ok())
        .or(file_config.reload)
        .unwrap_or(0);
    
    // Max requests
    let max_requests = cli_matches.value_of("max-requests")
        .and_then(|v| v.parse::<usize>().ok())
        .or(file_config.max_requests)
        .unwrap_or(0);
    
    // Stats interval
    let _stats_interval = cli_matches.value_of("stats-interval")
        .and_then(|v| v.parse::<u64>().ok())
        .or(file_config.stats_interval)
        .unwrap_or(0);
    
    // Query log
    let query_log = cli_matches.value_of("query-log")
        .map(String::from)
        .or(file_config.query_log);
    
    // DBL save
    let dbl_save = cli_matches.value_of("dbl-save")
        .map(String::from)
        .or(file_config.dbl_save);
    
    // Exempt IPs (à parser après)
    let mut exempt_ips = Vec::new();
    
    // Depuis la ligne de commande
    if let Some(no_limit_input) = cli_matches.value_of("no-request-limit") {
        for item in no_limit_input.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            
            match utils::parse_ip_or_cidr(item) {
                Ok(network) => exempt_ips.push(network),
                Err(e) => warn!("Invalid IP or CIDR in --no-request-limit: {} ({})", item, e),
            }
        }
    }
    
    // Depuis le fichier
    if let Some(no_limit_file) = &file_config.no_request_limit_file {
        if let Ok(ips) = read_ip_list_file(no_limit_file) {
            exempt_ips.extend(ips);
        } else {
            warn!("Failed to read no-request-limit-file: {}", no_limit_file);
        }
    }
    
    // Deny IPs
    let mut deny_ips = Vec::new();
    let deny_file = cli_matches.value_of("deny-file")
        .map(String::from)
        .or(file_config.deny_file);
    
    if let Some(deny_file) = deny_file {
        if let Ok(ips) = read_ip_list_file(&deny_file) {
            deny_ips = ips;
        } else {
            warn!("Failed to read deny-file: {}", deny_file);
        }
    }
    
    let access_control = AccessControl::new(
        max_requests,
        exempt_ips,
        deny_ips,
    );
    
    (interface, verbose, daemon, log_file, reload, access_control, query_log, dbl_save)
}

pub fn parse_args() -> Result<(Vec<ZoneConfig>, String, bool, bool, Option<String>, u64, 
                              AccessControl, Option<String>, Option<String>), String> {
    let matches = App::new("DNSBL Server")
        .version("2.9.0")
        .author("Philippe TEMESI")
        .about("A multi-zone DNSBL server with NS/SOA/MX/TXT record support and real-time DNSBL forwarding")
        // Options globales
        .arg(Arg::with_name("config")
            .long("config")
            .value_name("FILE")
            .help("Configuration file (INI format)")
            .takes_value(true))
        .arg(Arg::with_name("reload")
            .short("R")
            .long("reload")
            .value_name("MINUTES")
            .help("Auto-reload interval in minutes")
            .takes_value(true))
        .arg(Arg::with_name("max-requests")
            .long("max-requests")
            .value_name("COUNT")
            .help("Maximum number of requests per minute per IP (0 = unlimited)")
            .takes_value(true))
        .arg(Arg::with_name("no-request-limit")
            .long("no-request-limit")
            .value_name("IP,RANGE,...")
            .help("Comma-separated list of IPs or CIDR ranges exempt from rate limiting")
            .takes_value(true))
        .arg(Arg::with_name("no-request-limit-file")
            .long("no-request-limit-file")
            .value_name("FILE")
            .help("File containing IPs or CIDR ranges exempt from rate limiting (one per line)")
            .takes_value(true))
        .arg(Arg::with_name("deny-file")
            .long("deny-file")
            .value_name("FILE")
            .help("File containing IPs or CIDR ranges not allowed to query the server (one per line)")
            .takes_value(true))
        .arg(Arg::with_name("stats-interval")
            .long("stats-interval")
            .value_name("SECONDS")
            .help("Interval for rate limiting stats logging (0 = disabled)")
            .takes_value(true))
        .arg(Arg::with_name("query-log")
            .long("query-log")
            .value_name("FILE")
            .help("Log all DNS queries to this file")
            .takes_value(true))
        .arg(Arg::with_name("dbl-save")
            .long("dbl-save")
            .value_name("FILE")
            .help("Save IPs found in remote DNSBLs to this file (one IP per line)")
            .takes_value(true))
        .arg(Arg::with_name("daemon")
            .short("d")
            .long("daemon")
            .help("Run in daemon mode"))
        .arg(Arg::with_name("no-daemon")
            .long("no-daemon")
            .help("Do not run in daemon mode (override config file)"))
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Listening interface")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Verbose mode"))
        .arg(Arg::with_name("log")
            .short("l")
            .long("log")
            .value_name("LOG_FILE")
            .help("Log file")
            .takes_value(true))
        // Options de zone (uniquement en CLI si pas de config)
        .arg(Arg::with_name("domain")
            .short("D")
            .long("domain")
            .value_name("DOMAIN")
            .help("DNSBL domain (cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("response")
            .short("r")
            .long("response")
            .value_name("IP")
            .help("Response IP for blocked queries (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("self-ip")
            .short("s")
            .long("self-ip")
            .value_name("IP")
            .help("IP address to return for A/NS/SOA queries on the domain itself (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("txt")
            .long("txt")
            .value_name("TEXT")
            .help("TXT record for the domain (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("mx")
            .long("mx")
            .value_name("SERVER,PRIORITY")
            .help("MX record for the domain (format: server,priority) (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_name("SOURCE")
            .help("Blocklist source (file, http://, https://, or dnsbl://domain) (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .arg(Arg::with_name("file-list")
            .short("F")
            .long("file-list")
            .value_name("FILE")
            .help("File containing one source per line (per zone, cannot be used with --config)")
            .takes_value(true)
            .multiple(true)
            .conflicts_with("config"))
        .get_matches();
    
    // Vérifier si on utilise un fichier de config
    if let Some(config_file) = matches.value_of("config") {
        info!("Loading configuration from: {}", config_file);
        
        let (file_global, mut file_zones) = parse_config_file(config_file)?;
        
        // Vérifier qu'il y a au moins une zone
        if file_zones.is_empty() {
            return Err("No zones defined in configuration file".to_string());
        }
        
        // Charger les sources depuis les source-files
        for zone in &mut file_zones {
            for source_file in &zone.source_files {
                match read_source_file(source_file) {
                    Ok(sources) => {
                        info!("Loaded {} sources from file: {} for zone {}", 
                              sources.len(), source_file, zone.domain);
                        zone.sources.extend(sources);
                    }
                    Err(e) => {
                        warn!("Failed to read source-file {} for zone {}: {}", 
                              source_file, zone.domain, e);
                    }
                }
            }
        }
        
        // Fusionner avec les options CLI
        let (interface, verbose, daemon, log_file, reload, access_control, query_log, dbl_save) = 
            merge_configs(&matches, file_global);
        
        Ok((file_zones, interface, verbose, daemon, log_file, reload, access_control, query_log, dbl_save))
        
    } else {
        // Mode CLI traditionnel (compatible avec ancienne version)
        info!("Using command-line configuration (legacy mode)");
        
        let reload_minutes = matches.value_of("reload").unwrap_or("0").parse::<u64>()
            .map_err(|_| "Invalid reload interval")?;
        
        let max_requests = matches.value_of("max-requests").unwrap_or("0").parse::<usize>()
            .map_err(|_| "Invalid max-requests value")?;
        
        let _stats_interval = matches.value_of("stats-interval").unwrap_or("0").parse::<u64>()
            .map_err(|_| "Invalid stats-interval value")?;
        
        let query_log = matches.value_of("query-log").map(String::from);
        let dbl_save = matches.value_of("dbl-save").map(String::from);
        
        let mut exempt_ips = Vec::new();
        
        if let Some(no_limit_input) = matches.value_of("no-request-limit") {
            for item in no_limit_input.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                
                match utils::parse_ip_or_cidr(item) {
                    Ok(network) => {
                        exempt_ips.push(network);
                        info!("Added exempt network from CLI: {}", network);
                    }
                    Err(e) => {
                        return Err(format!("Invalid IP or CIDR range in --no-request-limit: {} ({})", item, e));
                    }
                }
            }
        }
        
        if let Some(no_limit_file) = matches.value_of("no-request-limit-file") {
            match read_ip_list_file(no_limit_file) {
                Ok(ips) => {
                    info!("Loaded {} exempt IPs/ranges from file: {}", ips.len(), no_limit_file);
                    exempt_ips.extend(ips);
                }
                Err(e) => {
                    return Err(format!("Error reading no-request-limit-file {}: {}", no_limit_file, e));
                }
            }
        }
        
        let mut deny_ips = Vec::new();
        if let Some(deny_file) = matches.value_of("deny-file") {
            match read_ip_list_file(deny_file) {
                Ok(ips) => {
                    info!("Loaded {} denied IPs/ranges from file: {}", ips.len(), deny_file);
                    deny_ips = ips;
                }
                Err(e) => {
                    return Err(format!("Error reading deny-file {}: {}", deny_file, e));
                }
            }
        }
        
        let domains = matches.values_of_lossy("domain").unwrap_or_else(|| vec!["dnsbl.tems.be".to_string()]);
        let responses = matches.values_of_lossy("response").unwrap_or_else(|| vec!["127.0.0.2".to_string()]);
        let self_ips = matches.values_of_lossy("self-ip").unwrap_or_else(|| {
            vec!["127.0.0.2".to_string()]
        });
        
        let txt_records_all = matches.values_of_lossy("txt").unwrap_or_default();
        let mx_records_all = matches.values_of_lossy("mx").unwrap_or_default();
        
        if domains.len() != responses.len() {
            return Err(format!(
                "Number of domains ({}) must match number of response IPs ({})",
                domains.len(), responses.len()
            ));
        }
        
        if domains.len() != self_ips.len() {
            return Err(format!(
                "Number of domains ({}) must match number of self IPs ({})",
                domains.len(), self_ips.len()
            ));
        }
        
        let mut all_sources = matches.values_of_lossy("file").unwrap_or_default();
        
        if let Some(file_lists) = matches.values_of_lossy("file-list") {
            for list_file in file_lists {
                match read_source_file(&list_file) {
                    Ok(sources) => {
                        info!("Loaded {} sources from file: {}", sources.len(), list_file);
                        all_sources.extend(sources);
                    }
                    Err(e) => {
                        return Err(format!("Error reading file list {}: {}", list_file, e));
                    }
                }
            }
        }
        
        let mut zone_configs = Vec::new();
        let mut source_index = 0;
        
        for i in 0..domains.len() {
            let response_ip = Ipv4Addr::from_str(&responses[i])
                .map_err(|_| format!("Invalid response IP: {}", responses[i]))?;
            
            let self_ip = Ipv4Addr::from_str(&self_ips[i])
                .map_err(|_| format!("Invalid self IP: {}", self_ips[i]))?;
            
            let mut zone_sources = Vec::new();
            
            if i < domains.len() - 1 {
                let sources_per_zone = if !all_sources.is_empty() { all_sources.len() / domains.len() } else { 0 };
                let start = i * sources_per_zone;
                let end = start + sources_per_zone;
                for j in start..end.min(all_sources.len()) {
                    zone_sources.push(all_sources[j].clone());
                }
            } else {
                while source_index < all_sources.len() {
                    zone_sources.push(all_sources[source_index].clone());
                    source_index += 1;
                }
            }
            
            let mut zone_txt = Vec::new();
            let mut zone_mx = Vec::new();
            
            if i < txt_records_all.len() {
                zone_txt.push(TxtRecord {
                    text: txt_records_all[i].clone(),
                });
            }
            
            if i < mx_records_all.len() {
                let parts: Vec<&str> = mx_records_all[i].split(',').collect();
                if parts.len() == 2 {
                    if let Ok(priority) = parts[1].parse::<u16>() {
                        zone_mx.push(MxRecord {
                            server: parts[0].to_string(),
                            priority,
                        });
                    } else {
                        warn!("Invalid MX priority for {}: {}", domains[i], mx_records_all[i]);
                    }
                } else {
                    warn!("Invalid MX format for {}: {} (expected server,priority)", 
                          domains[i], mx_records_all[i]);
                }
            }
            
            zone_configs.push(ZoneConfig {
                domain: domains[i].clone(),
                response_ip,
                self_ip,
                txt_records: zone_txt,
                mx_records: zone_mx,
                sources: zone_sources,
                source_files: Vec::new(),
            });
        }
        
        let access_control = AccessControl::new(
            max_requests,
            exempt_ips,
            deny_ips,
        );
        
        Ok((
            zone_configs,
            matches.value_of("interface").unwrap_or("0.0.0.0:53").to_string(),
            matches.is_present("verbose"),
            matches.is_present("daemon") && !matches.is_present("no-daemon"),
            matches.value_of("log").map(String::from),
            reload_minutes,
            access_control,
            query_log,
            dbl_save,
        ))
    }
}

