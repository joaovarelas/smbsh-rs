use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "SMB Share Scanner", about = "Scan for SMB shares across hosts")]
pub struct Args {
    /// Username for authentication
    #[arg(short, long)]
    pub username: Option<String>,

    /// Password for authentication
    #[arg(short, long)]
    pub password: Option<String>,

    /// Domain or workgroup name
    #[arg(short, long)]
    pub domain: Option<String>,

    /// Host, file with hosts, or CIDR range (e.g. 192.168.1.0/24)
    #[arg(required = true)]
    pub target: String,

    /// Number of concurrent workers
    #[arg(short, long, default_value_t = 128)]
    pub workers: usize,

    /// Connection timeout in seconds
    #[arg(short, long, default_value_t = 2)]
    pub timeout: u64,
}
