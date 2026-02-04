use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "idarasyn")]
#[command(about = "High-speed TCP SYN port scanner", long_about = None)]
pub struct Args {
    #[arg(help = "Target IP address to scan")]
    pub target: String,

    #[arg(short, long, default_value = "1-1000", help = "Port range (e.g., 80,443 or 1-1000)")]
    pub ports: String,

    #[arg(short, long, help = "Network interface to use (auto-detected if not specified)")]
    pub interface: Option<String>,

    #[arg(short = 's', long, default_value_t = 50000, help = "Source port for scanning")]
    pub source_port: u16,

    #[arg(short = 'r', long, default_value_t = 100, help = "Rate limit (packets per burst)")]
    pub rate_limit: usize,

    #[arg(short = 'j', long, default_value_t = 50, help = "Maximum jitter between bursts (ms)")]
    pub jitter: u64,

    #[arg(short = 't', long, default_value_t = 10, help = "Timeout for response listening (seconds)")]
    pub timeout: u64,

    #[arg(short = 'b', long, help = "Enable banner grabbing for open ports")]
    pub banner_grab: bool,

    #[arg(long, default_value_t = 3, help = "Banner grab timeout (seconds)")]
    pub banner_timeout: u64,

    #[arg(long, help = "Output results in JSON format")]
    pub json: bool,
}
