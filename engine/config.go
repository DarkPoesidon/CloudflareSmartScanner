package engine

// Cloudflare-supported ports for proxied traffic.
var (
	CFHTTPSPorts = []int{443, 2053, 2083, 2087, 2096, 8443}
	CFHTTPPorts  = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}
)

// ScanConfig holds all tunable parameters for the scanner.
// Exported to allow gomobile bindings for the mobile app.
type ScanConfig struct {
	InputFile     string // Path to target list (e.g., "domains.txt")
	CacheFile     string // Path to last_passed.txt
	OutputDir     string // Output directory for reports and cache (mobile: Context.getFilesDir())
	TimeoutSecs   int    // Per-request timeout limit (default 10)
	MaxConcurrent int    // Worker pool size (default 80)
	RetryCount    int    // HTTP retry count (default 2)
	UserAgent     string // Custom User-Agent header
	ScanAllPorts  bool   // If true, expand each target across all 13 Cloudflare ports
	SpoofedSNI    string // The fake SNI to use for bypassing DPI filtering

	// DNS Discovery Mode fields
	DnsDiscoveryMode bool   // If true, input file is treated as DNS resolver IPs and the engine runs DNS probes
	TargetDomain     string // Domain used for integrity verification against truth table (default "google.com")
}

// DefaultConfig returns a pre-configured config mimicking the original Python settings.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		InputFile:        "domains.txt",
		CacheFile:        "last_passed.txt",
		OutputDir:        ".",
		TimeoutSecs:      10,
		MaxConcurrent:    80,
		RetryCount:       2,
		UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		ScanAllPorts:     false,
		SpoofedSNI:       "www.speedtest.net",
		DnsDiscoveryMode: false,
		TargetDomain:     "google.com",
	}
}
