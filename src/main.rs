mod args;
mod scan;

use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use futures::stream::{self, StreamExt};
use ipnetwork::IpNetwork;
use tokio::sync::Mutex;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args = args::Args::parse();

    // Process the target - file, CIDR, or single host
    let targets = get_targets(&args.target)?;

    println!("SMB Share Scanner");
    println!("Workers: {}", args.workers);
    println!("Target(s): {} ({} hosts)", args.target, targets.len());

    // Collect results in a thread-safe vector
    let results = Arc::new(Mutex::new(Vec::new()));

    let alive_hosts = scan::check_alive_hosts(
        targets,
        445,
        Duration::from_secs(args.timeout),
        args.workers,
    )
    .await?;

    println!("{:?}", alive_hosts);

    if !alive_hosts.is_empty() {
        // Print header
        println!(
            "\n{:<6} {:<15} {:<5} {:<15} {:<20} {:<12} {:<}",
            "PROTO", "IP/HOST", "PORT", "HOSTNAME", "SHARE", "PERMISSIONS", "COMMENTS"
        );
        println!("{:-<90}", "");

        // Process hosts concurrently with limited parallelism
        stream::iter(alive_hosts)
            .map(|server| {
                let username = args.username.clone();
                let password = args.password.clone();
                let domain = args.domain.clone();
                let timeout = args.timeout;
                let results_clone = Arc::clone(&results);

                async move {
                    let scan_results = scan::scan_server_smb(
                        &server,
                        username.unwrap_or_default(),
                        password.unwrap_or_default(),
                        domain.unwrap_or_default(),
                        timeout,
                    )
                    .await;

                    // If we found shares, add them to results
                    if !scan_results.is_empty() {
                        let mut results = results_clone.lock().await;
                        results.extend(scan_results.clone());

                        // Print results immediately
                        for result in &scan_results {
                            println!(
                                "\r{:<6} {:<15} {:<5} {:<15} {:<20} {:<12} {:<}",
                                "SMB",
                                result.server,
                                result.port,
                                result.hostname,
                                result.share_name,
                                result.permissions,
                                result.comment
                            );
                        }
                    }
                }
            })
            .buffer_unordered(args.workers)
            .collect::<Vec<()>>()
            .await;
    }

    println!("\r\nScan complete!");

    Ok(())
}

// Parse target argument to get a list of hosts to scan
fn get_targets(target: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Check if target is a file
    if Path::new(target).exists() {
        // Read hosts from file
        let content = fs::read_to_string(target)?;
        let hosts = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        return Ok(hosts);
    }

    // Check if target is a CIDR range
    if target.contains('/') {
        let network = IpNetwork::from_str(target)?;
        let hosts = network.iter().map(|ip| ip.to_string()).collect();
        return Ok(hosts);
    }

    // Single host or hostname
    Ok(vec![target.to_string()])
}
