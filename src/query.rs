use std::net::{UdpSocket, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use clap::{App, Arg};
use log::{info, error, debug};
use rand::Rng;

use trust_dns_proto::op::{Message, MessageType, Query, ResponseCode};
use trust_dns_proto::rr::{Name, RecordType, RData};
use trust_dns_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};

// Structure for DNSBL query tool
#[derive(Debug)]
struct DNSBLQuery {
    domain: String,
    dns_server: Option<String>,
    ip: Ipv4Addr,
}

impl DNSBLQuery {
    fn new(domain: &str, dns_server: Option<String>, ip: Ipv4Addr) -> Self {
        DNSBLQuery {
            domain: domain.to_string(),
            dns_server,
            ip,
        }
    }

    // Convert IP to reverse DNSBL format
    fn ip_to_dnsbl_format(&self) -> String {
        let octets = self.ip.octets();
        format!("{}.{}.{}.{}.{}", 
            octets[3], octets[2], octets[1], octets[0], 
            self.domain
        )
    }

    // Create DNS query packet
    fn create_dns_query(&self) -> Result<Vec<u8>, String> {
        let query_name = self.ip_to_dnsbl_format();
        debug!("Query domain: {}", query_name);
        
        // Parse domain name
        let name = Name::from_str(&query_name)
            .map_err(|e| format!("Invalid domain name: {}", e))?;
        
        // Create query
        let query = Query::query(name, RecordType::A);
        
        // Create message
        let mut message = Message::new();
        message.set_id(rand::thread_rng().gen::<u16>());
        message.set_message_type(MessageType::Query);
        message.add_query(query);
        message.set_recursion_desired(true);
        
        // Encode message
        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder)
            .map_err(|e| format!("Failed to encode DNS query: {}", e))?;
        
        Ok(bytes)
    }

    // Parse DNS response
    fn parse_dns_response(&self, response: &[u8]) -> Result<Option<Ipv4Addr>, String> {
        let mut decoder = BinDecoder::new(response);
        let message = Message::read(&mut decoder)
            .map_err(|e| format!("Failed to parse DNS response: {}", e))?;
        
        debug!("DNS Response ID: {}", message.id());
        debug!("Response type: {:?}", message.message_type());
        debug!("Response code: {:?}", message.response_code());
        
        if message.response_code() != ResponseCode::NoError {
            if message.response_code() == ResponseCode::NXDomain {
                return Ok(None);
            }
            return Err(format!("DNS error: {}", message.response_code()));
        }
        
        // Extract answers
        let answers = message.answers();
        
        for answer in answers {
            if answer.record_type() == RecordType::A {
                if let Some(RData::A(addr)) = answer.data() {
                    let ip = Ipv4Addr::from(addr.octets());
                    debug!("Found A record: {}", ip);
                    return Ok(Some(ip));
                }
            }
        }
        
        Ok(None)
    }

    // Perform DNSBL query
    fn query(&self, timeout: u64) -> Result<Option<Ipv4Addr>, String> {
        let query_data = self.create_dns_query()?;
        let dnsbl_domain = self.ip_to_dnsbl_format();
        
        // Determine DNS server
        let socket_addr = match &self.dns_server {
            Some(server) => {
                if server.contains(':') {
                    SocketAddr::from_str(server)
                        .map_err(|e| format!("Invalid DNS server address: {}", e))?
                } else {
                    SocketAddr::from_str(&format!("{}:53", server))
                        .map_err(|e| format!("Invalid DNS server address: {}", e))?
                }
            }
            None => {
                // Use system default (127.0.0.1:53)
                SocketAddr::from_str("127.0.0.1:53")
                    .map_err(|e| format!("Invalid default DNS server: {}", e))?
            }
        };
        
        info!("Querying {} for {} -> {}", 
            socket_addr, dnsbl_domain, self.ip);
        
        // Create UDP socket
        let local_addr = if socket_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        
        let socket = UdpSocket::bind(local_addr)
            .map_err(|e| format!("Failed to create UDP socket: {}", e))?;
        
        socket.set_read_timeout(Some(Duration::from_secs(timeout)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;
        
        // Send query
        debug!("Sending {} bytes to {}", query_data.len(), socket_addr);
        socket.send_to(&query_data, socket_addr)
            .map_err(|e| format!("Failed to send DNS query: {}", e))?;
        
        // Receive response
        let mut buf = [0u8; 512];
        let (size, _) = socket.recv_from(&mut buf)
            .map_err(|e| format!("Failed to receive DNS response: {}", e))?;
        
        debug!("Received {} bytes", size);
        
        // Parse response
        self.parse_dns_response(&buf[..size])
    }
}

// Setup logging
fn setup_logging(verbose: bool, quiet: bool) -> Result<(), fern::InitError> {
    let log_level = if quiet {
        log::LevelFilter::Error
    } else if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}] {}",
                record.level(),
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .apply()?;
    
    Ok(())
}

fn main() {
    let matches = App::new("DNSBL Query Tool")
        .version("1.0")
        .author("Philippe TEMESI")
        .about("Query a DNSBL server to check if an IP is listed")
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .value_name("DOMAIN")
                .help("DNSBL domain (e.g., dnsbl.tems.be)")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .value_name("SERVER")
                .help("DNS server to use (default: system DNS on 127.0.0.1:53)")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("ip")
                .help("IP address to check (e.g., 192.168.1.100)")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Verbose output")
                .conflicts_with("quiet")
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Quiet mode (only output result)")
                .conflicts_with("verbose")
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .value_name("SECONDS")
                .help("DNS query timeout in seconds")
                .takes_value(true)
                .default_value("5")
        )
        .after_help("2026, Philippe TEMESI - https://www.tems.be\n\nExamples:\n  dnsbl-query -d dnsbl.tems.be 192.168.1.100\n  dnsbl-query -d dnsbl.tems.be -s 8.8.8.8 192.168.1.100\n  dnsbl-query -d dnsbl.tems.be -s 127.0.0.1:5453 -v 192.168.1.100")
        .get_matches();

    // Setup logging
    let verbose = matches.is_present("verbose");
    let quiet = matches.is_present("quiet");
    
    if let Err(e) = setup_logging(verbose, quiet) {
        eprintln!("Logging initialization error: {}", e);
        std::process::exit(1);
    }

    // Parse arguments
    let domain = matches.value_of("domain").unwrap();
    let dns_server = matches.value_of("server").map(String::from);
    let ip_str = matches.value_of("ip").unwrap();
    let timeout: u64 = matches.value_of("timeout")
        .unwrap()
        .parse()
        .unwrap_or(5);
    
    // Validate IP address
    let ip = match Ipv4Addr::from_str(ip_str) {
        Ok(ip) => ip,
        Err(_) => {
            error!("Invalid IPv4 address: {}", ip_str);
            std::process::exit(1);
        }
    };
    
    // Create query tool
    let query = DNSBLQuery::new(domain, dns_server, ip);
    
    if !quiet {
        info!("DNSBL Query Tool v1.0 - 2026, Philippe TEMESI");
        info!("Querying DNSBL domain: {}", query.domain);
    }
    
    // Perform query
    match query.query(timeout) {
        Ok(Some(response_ip)) => {
            if quiet {
                // Quiet mode: just print the result
                println!("BLOCKED:{}", response_ip);
            } else {
                info!("✅ IP {} is BLOCKED by DNSBL", ip);
                info!("   DNSBL domain: {}", query.ip_to_dnsbl_format());
                info!("   Response IP: {}", response_ip);
                
                // Interpret common DNSBL response codes
                match response_ip.octets() {
                    [127, 0, 0, 2] => info!("   Reason: General spam source"),
                    [127, 0, 0, 3] => info!("   Reason: High confidence spam"),
                    [127, 0, 0, 4] => info!("   Reason: Open proxy"),
                    [127, 0, 0, 5] => info!("   Reason: Open relay"),
                    [127, 0, 0, 6] => info!("   Reason: Hacked/Compromised"),
                    [127, 0, 0, 7] => info!("   Reason: Dynamic IP"),
                    [127, 0, 0, 8] => info!("   Reason: Dialup IP"),
                    [127, 0, 0, 9] => info!("   Reason: Blacklisted"),
                    _ => info!("   Response code: {}", response_ip),
                }
            }
        }
        Ok(None) => {
            if quiet {
                println!("CLEAN");
            } else {
                info!("✅ IP {} is CLEAN (not listed in DNSBL)", ip);
            }
        }
        Err(e) => {
            if quiet {
                println!("ERROR:{}", e);
            } else {
                error!("❌ Query failed: {}", e);
            }
            std::process::exit(1);
        }
    }
}
