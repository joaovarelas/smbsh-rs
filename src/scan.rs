use pavao::{SmbClient, SmbCredentials, SmbOptions, SmbStat};

use futures::stream::{self, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

#[derive(Clone)]
pub struct ScanResult {
    pub server: String,
    pub port: u16,
    pub hostname: String,
    pub share_name: String,
    pub permissions: String,
    pub comment: String,
}

// Scan a single server for SMB shares
pub async fn scan_server_smb(
    server: &str,
    username: String,
    password: String,
    domain: String,
    timeout_secs: u64,
) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let port = 445; // SMB port

    // Set up client with server information
    let credentials = SmbCredentials::default()
        .server(&format!("smb://{}", server))
        .workgroup(&domain)
        .username(&username)
        .password(&password);

    // Create options with timeout
    let options = SmbOptions::default()
        .encryption_level(pavao::SmbEncryptionLevel::None)
        .fallback_after_kerberos(true);
    // .timeout(Duration::from_secs(timeout_secs));

    // Try to connect and list shares
    match SmbClient::new(credentials, options) {
        Ok(client) => {
            let _ = client.set_timeout(Duration::from_secs(timeout_secs));

            // Get hostname (use server address if can't get hostname)
            let hostname = match client.get_netbios_name() {
                Ok(name) => name,
                Err(_) => server.to_string(),
            };

            // Try to list the root directory
            match client.list_dir("") {
                Ok(entries) => {
                    for entry in entries {
                        let name = entry.name();
                        if name != "." && name != ".." {
                            // Try to get share permissions
                            let share_path = format!("/{}", name);
                            let permissions = match client.stat(&share_path) {
                                Ok(stat) => format_permissions(&stat),
                                Err(_) => "--".to_string(),
                            };

                            results.push(ScanResult {
                                server: server.to_string(),
                                port,
                                hostname: hostname.clone(),
                                share_name: name.to_string(),
                                permissions,
                                comment: entry.comment().to_string(),
                            });
                        }
                    }
                }
                Err(_) => {
                    // Failed to list shares - this is normal for many hosts, so we silently ignore
                }
            }
        }
        Err(_) => {
            // Failed to connect - this is normal for many hosts, so we silently ignore
        }
    }

    results
}

// Format permissions as a string
fn format_permissions(stat: &SmbStat) -> String {
    let mode = stat.mode;
    let read = if mode.user().read() { "R" } else { "-" };
    let write = if mode.user().write() { "W" } else { "-" };
    format!("{}{}", read, write)
}

async fn tcp_syn_scan(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<bool, Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let result = timeout(timeout_duration, TcpStream::connect(&addr)).await;

    match result {
        Ok(Ok(_)) => Ok(true), // Host is alive, TCP connection successful
        _ => Ok(false),        // Host is down or connection attempt failed
    }
}

pub async fn check_alive_hosts(
    targets: Vec<String>,
    port: u16,
    timeout_duration: Duration,
    workers: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let results = Arc::new(Mutex::new(Vec::new()));

    stream::iter(targets)
        .map(|host| {
            let results_clone = Arc::clone(&results);
            async move {
                if tcp_syn_scan(&host, port, timeout_duration)
                    .await
                    .unwrap_or(false)
                {
                    let mut results = results_clone.lock().await;
                    results.push(host);
                }
            }
        })
        .buffer_unordered(workers)
        .collect::<Vec<()>>()
        .await;

    let alive_hosts = Arc::try_unwrap(results).unwrap().into_inner(); //.unwrap();
    Ok(alive_hosts)
}
