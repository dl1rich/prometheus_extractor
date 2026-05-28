<img width="854" height="805" alt="image" src="https://github.com/user-attachments/assets/27625456-92dc-431c-8a4e-d8f4cb86c8e0" /># Prometheus Attack Surface Enumerator

A comprehensive reconnaissance and security analysis tool for Prometheus servers. This tool transforms from a simple metrics parser into a full-featured attack surface enumerator, providing operator-useful intelligence, security findings, and infrastructure discovery.

## Screenshots

(HTML report) 
<img width="1152" height="1202" alt="image" src="https://github.com/user-attachments/assets/ec815f67-0cdd-4ac6-9ec1-d9c0c06c225c" />

(Terminal output)
<img width="854" height="805" alt="image" src="https://github.com/user-attachments/assets/455ba61e-724d-40f9-bae2-31e57b708bd7" />


## Features

### Core Capabilities

- **Endpoint Discovery**: Automatically enumerate 25+ Prometheus API endpoints
- **API Enumeration**: Query and extract data from multiple Prometheus APIs
- **Configuration Extraction**: Retrieve and analyze Prometheus configuration (including sensitive data)
- **Target Enumeration**: List all active and dropped scrape targets with full URLs
- **Service Discovery**: Detect and enumerate SD mechanisms (Kubernetes, Consul, EC2, Azure, GCP, etc.)
- **Rules & Alerts**: Extract recording rules, alerting rules, and active alerts
- **Label Harvesting**: Enumerate all labels and their values for service discovery
- **PromQL Support**: Execute custom PromQL queries
- **Performance Analysis**: Extract TSDB statistics, WAL size, query durations, and scrape metrics
- **Security Assessment**: Check for exposed debug endpoints (pprof, fgprof), sensitive data, and misconfigurations
- **Kubernetes Discovery**: Enumerate namespaces, pods, nodes, and services from metrics
- **Federation Detection**: Detect if federation endpoint is enabled
- **Remote Storage**: Identify remote write/read configurations
- **HTML Report Generation**: Create professional HTML reports with CSS styling
- **Full Data Dumps**: Optional --full-output flag for complete config/target/rule dumps
- **Windows Compatible**: ASCII-only output for Windows PowerShell/CMD compatibility

### Intelligence Extraction

The tool extracts and presents operator-useful information including:

- **Prometheus Version & Build Info** with full URLs to status endpoints
- **Memory Usage & Resource Statistics** (goroutines, open FDs, memory consumption)
- **TSDB Size, WAL Size, Retention Period** with performance warnings
- **Active Target Count & Health Status** with full scrape URLs
- **Failed Scrape Targets** (valuable for finding internal services)
- **Scrape Job Enumeration** with target counts per job
- **Query Performance (p50, p99)** with slow query warnings
- **Kubernetes Cluster Information** (namespaces, nodes, pods, services)
- **Active Alerts & Alertmanagers** with full alert URLs
- **Internal IP Addresses & Hostnames** extracted from metrics/configs
- **Sensitive Keyword Detection** (passwords, tokens, credentials in configs)
- **Debug Endpoint Exposure (pprof, fgprof)** with direct access URLs
- **Admin API Availability** and lifecycle endpoints
- **Full Configuration Dumps** (optional with --full-output flag)
- **Complete Target Lists** with scrape URLs (optional with --full-output flag)

### Security Checks

- **pprof debug endpoint detection** with full URLs for heap/goroutine dumps
- **fgprof debug endpoint detection** for profiling data
- **Config API accessibility** with sensitive data extraction (bearer tokens, passwords)
- **Federation endpoint status** for metrics scraping
- **Admin API enabled check** (snapshot creation, TSDB management)
- **Lifecycle API enabled check** (reload, quit endpoints)
- **Sensitive keyword scanning** in configs (password, token, secret, key)
- **Private IP address extraction** (RFC1918 ranges)
- **Internal hostname discovery** from metrics and targets
- **Credential leak detection** in configuration files
- **Service discovery credentials** (Kubernetes tokens, Consul ACLs, cloud credentials)

### Output Formats

- **Interactive Terminal Report**: ASCII-only output with color-coded findings (Windows compatible)
- **HTML Report**: Professional styled report with CSS, responsive layout, severity badges
- **JSON**: Complete structured data export with all findings
- **CSV**: Flat metric data for spreadsheet analysis
- **Raw JSON**: Unparsed metric data for further processing

## Installation

```bash
# Clone or download the script
git clone <repo-url>
cd prometheus_extractor

# Install dependencies
pip install requests
```

## Usage

### Basic Usage

```bash
# Full enumeration of Prometheus server
python prometheus_extract.py --url http://prometheus.example.com:9090

# With timeout for slow servers
python prometheus_extract.py --url http://10.0.2.30:9090 --timeout 30

# Analyze metrics from a file
python prometheus_extract.py --file metrics.txt
```

### Advanced Usage

```bash
# With authentication
python prometheus_extract.py --url http://prometheus:9090 \
    --header "Authorization: Bearer YOUR_TOKEN"

# Generate HTML report with full data dumps
python prometheus_extract.py --url http://prometheus:9090 \
    --html report.html --full-output

# Save full report to JSON with complete configs/targets
python prometheus_extract.py --url http://prometheus:9090 \
    --json full_report.json --full-output

# Execute PromQL query
python prometheus_extract.py --url http://prometheus:9090 \
    --query "up"

# Metrics-only analysis (skip API enumeration)
python prometheus_extract.py --url http://prometheus:9090 \
    --metrics-only

# Save to multiple formats with full output
python prometheus_extract.py --url http://prometheus:9090 \
    --json report.json \
    --html report.html \
    --csv metrics.csv \
    --full-output

# Silent mode (save to file only, no terminal output)
python prometheus_extract.py --url http://prometheus:9090 \
    --json report.json \
    --no-report
```

## Output Examples

### Executive Summary

```
================================================================================
EXECUTIVE SUMMARY
================================================================================

[*] Prometheus Server Information:
    Version: 3.2.0
    Go Version: go1.23.6
    Memory Usage: 1.24 GB
    Goroutines: 142
    Open FDs: 48

[*] Time Series Database:
    TSDB Size: 42.31 GB
    WAL Size: 2.14 GB
    Head Series: 1,245,832
    Head Samples: 45,283,921

[*] Scrape Targets:
    Active Targets: 88
    Failed Targets: 2 [!]
    Scrape Jobs: 14

[*] Security Findings:
    [!] pprof Debug Endpoint: EXPOSED
        http://10.0.2.30:9090/debug/pprof/
    Config API: ACCESSIBLE
        http://10.0.2.30:9090/api/v1/status/config
    Federation: ENABLED
        http://10.0.2.30:9090/federate
```

### Target Enumeration

```
================================================================================
TARGET ENUMERATION
================================================================================
[URL] http://10.0.2.30:9090/targets
[API] http://10.0.2.30:9090/api/v1/targets

[*] Total Active Targets: 88
[*] Total Dropped Targets: 12

[*] Scrape Jobs (14):
    - kubernetes-nodes: 8 targets
    - kubernetes-pods: 52 targets
    - prometheus: 1 targets
    - grafana: 1 targets
    - node-exporter: 12 targets
    - blackbox-exporter: 14 targets

[*] Health Status:
    [+] up: 86
    [!] down: 2
```

### Security Findings with Full URLs

```
================================================================================
SECURITY FINDINGS
================================================================================

[*] Internal/Private IP Addresses (24):
    - 10.0.1.10
    - 10.0.1.11
    - 10.0.2.30
    - 192.168.1.100
    ...

[*] Internal Hostnames (12):
    - grafana.internal
    - postgres-exporter.internal
    - redis-master.internal
    ...

[*] Debug Endpoints:
    pprof: EXPOSED [!]
           [URL] http://10.0.2.30:9090/debug/pprof/
           [ACTION] Try these endpoints:
                    http://10.0.2.30:9090/debug/pprof/heap
                    http://10.0.2.30:9090/debug/pprof/goroutine?debug=2
                    http://10.0.2.30:9090/debug/pprof/profile?seconds=30
    fgprof: Not accessible

[*] Sensitive Keywords in Config:
    - bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    - password: <found in scrape config>
```

### Kubernetes Discovery

```
================================================================================
KUBERNETES ENUMERATION
================================================================================
[TIP] Kubernetes metrics reveal full cluster topology
[ACTION] Query kube_pod_info, kube_node_info for detailed enumeration
[URL] http://10.0.2.30:9090/api/v1/query?query=kube_pod_info

[*] Namespaces (8):
    [!] kube-system
    [!] default
        monitoring
        production
        staging
        logging
        ingress-nginx
        cert-manager

[*] Nodes (8):
    - k8s-master-01
    - k8s-worker-01
    - k8s-worker-02
    - k8s-worker-03
```

### Actionable Recommendations

```
================================================================================
ACTIONABLE RECOMMENDATIONS
================================================================================

[CRITICAL]

  Finding: pprof Debug Endpoint Exposed
  Impact:  Memory dumps can leak sensitive data, credentials, and internal state
  Action:  Visit http://10.0.2.30:9090/debug/pprof/heap and 
           http://10.0.2.30:9090/debug/pprof/goroutine?debug=2

[HIGH]

  Finding: Configuration API Accessible
  Impact:  Full config may contain credentials and sensitive paths
  Action:  Review http://10.0.2.30:9090/api/v1/status/config for: 
           bearer_token, password, tls_config

  Finding: Federation Endpoint Enabled
  Impact:  Allows scraping all metrics from this Prometheus instance
  Action:  Query http://10.0.2.30:9090/federate?match[]={__name__!=""} 
           to export all metrics

--------------------------------------------------------------------------------
GENERAL NEXT STEPS:
--------------------------------------------------------------------------------

1. Query Interesting Metrics:
   curl 'http://10.0.2.30:9090/api/v1/query?query=up'
   curl 'http://10.0.2.30:9090/api/v1/query?query=node_uname_info'

2. Enumerate All Targets:
   curl 'http://10.0.2.30:9090/api/v1/targets' | jq .

3. Extract Configuration:
   curl 'http://10.0.2.30:9090/api/v1/status/config' | jq .

4. Download All Metrics via Federation:
   curl -G 'http://10.0.2.30:9090/federate' \
     --data-urlencode 'match[]={__name__!=""}'
```

## API Endpoints Enumerated

The tool automatically checks the following Prometheus endpoints:

- `/api/v1/status/config` - Configuration
- `/api/v1/status/runtimeinfo` - Runtime information
- `/api/v1/status/buildinfo` - Build information
- `/api/v1/status/flags` - Command-line flags
- `/api/v1/targets` - Scrape targets
- `/api/v1/targets/metadata` - Target metadata
- `/api/v1/rules` - Recording and alerting rules
- `/api/v1/alerts` - Active alerts
- `/api/v1/alertmanagers` - Alertmanager discovery
- `/api/v1/labels` - All label names
- `/api/v1/label/__name__/values` - All metric names
- `/api/v1/metadata` - Metric metadata
- `/api/v1/query` - PromQL queries
- `/federate` - Federation endpoint
- `/debug/pprof/` - pprof profiling
- `/debug/fgprof` - fgprof profiling
- `/-/healthy` - Health check
- `/-/ready` - Readiness check

## Use Cases

### Security Assessment
- Enumerate exposed Prometheus servers during penetration testing
- Identify debug endpoints and misconfigurations
- Extract internal IP addresses and hostnames
- Detect sensitive data exposure

### Infrastructure Discovery
- Map Kubernetes cluster topology
- Enumerate microservices and targets
- Discover service discovery mechanisms
- Identify monitoring coverage gaps

### Operational Intelligence
- Analyze Prometheus performance
- Identify failing scrape targets
- Review active alerts
- Assess TSDB health and size

### Compliance & Audit
- Document monitoring configuration
- Export target lists
- Review security posture
- Generate compliance reports

## Command-Line Options

```
usage: prometheus_extract.py [-h] (--url URL | --file FILE) [--json JSON]
                             [--html HTML] [--raw-json RAW_JSON] [--csv CSV]
                             [--query QUERY] [--metrics-only] [--no-report]
                             [--full-output] [--timeout TIMEOUT] [--header HEADER]

Prometheus Attack Surface Enumerator

required arguments (one of):
  --url URL             Prometheus server URL (e.g., http://host:9090)
  --file FILE           Metrics file to analyze

optional arguments:
  -h, --help            show this help message and exit
  --json JSON           Save full report to JSON file
  --html HTML           Generate HTML report with CSS styling
  --raw-json RAW_JSON   Save raw parsed metrics to JSON
  --csv CSV             Save flat metric samples to CSV
  --query QUERY         Execute PromQL query (requires --url)
  --metrics-only        Only parse /metrics endpoint (skip API enumeration)
  --no-report           Skip printing report (use with --json/--html)
  --full-output         Include complete config/target/rule dumps (sensitive!)
  --timeout TIMEOUT     HTTP timeout in seconds (default: 15)
  --header HEADER       HTTP header (format: "Name: Value", can use multiple)
```

### Key Flags Explained

- **--full-output**: When enabled, includes complete dumps of:
  - Full Prometheus configuration (YAML) including sensitive data
  - All target scrape URLs and labels
  - Complete alert/rule definitions
  - Full label value lists
  - WARNING: May expose credentials, tokens, and sensitive paths
  
- **--html**: Generates a professional HTML report with:
  - Responsive CSS styling and grid layout
  - Color-coded severity badges (CRITICAL, HIGH, MEDIUM, INFO)
  - Collapsible sections for large datasets
  - Summary cards with key metrics
  - Full dumps section (when --full-output is used)
  
- **--timeout**: Useful for slow/overloaded Prometheus servers:
  - Default is 15 seconds
  - Increase to 30-60 for large TSDB or slow networks
  - Each endpoint gets its own timeout
  
- **--header**: Add custom HTTP headers:
  - Authentication: `--header "Authorization: Bearer TOKEN"`
  - Multiple headers: `--header "X-Custom: value" --header "X-Other: value"`
  - Useful for authenticated Prometheus instances

## Use Cases

### Security Assessment / Penetration Testing
- Enumerate exposed Prometheus servers during penetration testing
- Identify debug endpoints and misconfigurations
- Extract internal IP addresses and hostnames for lateral movement
- Detect sensitive data exposure (credentials, tokens, paths)
- Map attack surface via target enumeration
- Find authentication bypass opportunities (admin API, pprof)

### Infrastructure Discovery
- Map Kubernetes cluster topology (namespaces, pods, nodes, services)
- Enumerate microservices and their endpoints
- Discover service discovery mechanisms and credentials
- Identify monitoring coverage and blind spots
- Extract cloud instance metadata (AWS, Azure, GCP)
- Understand application architecture from scrape targets

### Operational Intelligence
- Analyze Prometheus performance and resource usage
- Identify failing scrape targets and investigate
- Review active alerts and alerting rules
- Assess TSDB health, size, and retention
- Monitor query performance and bottlenecks
- Audit remote write/read configurations

### Compliance & Audit
- Document monitoring configuration for compliance
- Export complete target lists and scrape configs
- Review security posture and identify risks
- Generate compliance reports (JSON/HTML)
- Identify unauthorized monitoring or data exfiltration
- Audit service discovery and credential usage

## What This Tool Reveals

When pointed at a Prometheus server, this tool typically reveals:

### Infrastructure Intelligence
- Internal scrape targets and endpoints with full URLs
- Internal IP addresses and RFC1918 networks
- Kubernetes cluster structure (namespaces, pods, nodes)
- Cloud instance metadata (EC2, Azure, GCP)
- DNS names and internal hostnames
- Service discovery configurations (Kubernetes, Consul, cloud providers)

### Security-Relevant Data
- Debug endpoints (pprof, fgprof) with direct access URLs
- Admin API availability (snapshot, TSDB management, metric deletion)
- Federation exposure (allows full metrics export)
- Bearer token file paths (especially Kubernetes service accounts)
- Remote write/read endpoints and credentials
- Password/secret references in configurations
- Environment variable paths and values
- TLS certificate paths and configurations

### Operational Metrics
- Prometheus version and build information
- Memory usage and resource consumption (goroutines, FDs)
- TSDB size, WAL size, and retention period
- Query performance statistics (p50, p99, p99.9)
- Failed scrape targets and error reasons
- Active alerts and firing conditions
- Recording and alerting rule definitions
- Scrape job configurations and intervals

## Detection of Service Discovery Types

The tool automatically detects and reports on these service discovery mechanisms:

- `kubernetes_sd_configs` - Kubernetes service discovery (may contain API tokens)
- `consul_sd_configs` - Consul service discovery (may contain ACL tokens)
- `ec2_sd_configs` - AWS EC2 service discovery (IAM roles, access keys)
- `azure_sd_configs` - Azure service discovery (subscription IDs, credentials)
- `gce_sd_configs` - Google Cloud service discovery (project IDs, credentials)
- `dns_sd_configs` - DNS-based service discovery
- `file_sd_configs` - File-based service discovery (check file paths)
- `nomad_sd_configs` - Nomad service discovery
- `digitalocean_sd_configs` - DigitalOcean service discovery
- `docker_sd_configs` - Docker service discovery
- `dockerswarm_sd_configs` - Docker Swarm service discovery

## Why This Matters for Security

Prometheus servers often leak significant infrastructure information that's valuable for attackers:

1. **Attack Surface Mapping**: Discover all monitored services, their endpoints, and health status
2. **Lateral Movement**: Find internal IPs, hostnames, and service relationships to pivot
3. **Credential Discovery**: Config files frequently contain bearer tokens, API keys, passwords
4. **Cloud Metadata**: Service discovery configs reveal cloud infrastructure and credentials
5. **Kubernetes Enumeration**: Full cluster topology reveals privilege escalation paths
6. **Service Dependencies**: Understand application architecture and find weak points
7. **Memory Dumps**: pprof endpoints can leak credentials and sensitive runtime data
8. **Data Exfiltration**: Federation allows downloading all metrics without authentication

## API Endpoints Enumerated

The tool automatically checks 25+ Prometheus endpoints:

**Status Endpoints:**
- `/api/v1/status/config` - Full configuration (may contain credentials)
- `/api/v1/status/runtimeinfo` - Runtime and TSDB information
- `/api/v1/status/buildinfo` - Build and version information
- `/api/v1/status/flags` - Command-line flags
- `/api/v1/status/tsdb` - TSDB statistics and head stats

**Target & Discovery:**
- `/api/v1/targets` - All scrape targets with URLs and labels
- `/api/v1/targets/metadata` - Target metadata and metric types
- `/api/v1/labels` - All label names
- `/api/v1/label/<name>/values` - Values for specific labels
- `/api/v1/series` - Time series metadata

**Rules & Alerts:**
- `/api/v1/rules` - Recording and alerting rules
- `/api/v1/alerts` - Active alerts with firing status
- `/api/v1/alertmanagers` - Alertmanager discovery status

**Query & Metadata:**
- `/api/v1/query` - Execute PromQL queries
- `/api/v1/metadata` - Metric metadata (types, help text)
- `/federate` - Federation endpoint (exports all metrics)

**Debug & Admin:**
- `/debug/pprof/` - Go profiling endpoints (heap, goroutine, profile, etc.)
- `/debug/fgprof` - Full goroutine profiler
- `/api/v1/admin/tsdb/snapshot` - Create TSDB snapshot (POST)
- `/api/v1/admin/tsdb/delete_series` - Delete metrics (POST)
- `/api/v1/admin/tsdb/clean_tombstones` - Clean tombstones (POST)

**Health & Readiness:**
- `/-/healthy` - Health check endpoint
- `/-/ready` - Readiness check endpoint
- `/-/reload` - Reload configuration (POST, if lifecycle enabled)
- `/-/quit` - Shutdown server (POST, if lifecycle enabled)

## Security Considerations

**Authorized Use Only:**

This tool is designed for:
- Authorized security assessments and penetration testing
- Infrastructure documentation and inventory
- Compliance audits and security reviews
- Operational troubleshooting and performance analysis

**WARNING:** Only use against systems you own or have explicit written permission to test.

**Sensitive Data Handling:**

When using `--full-output` flag, be aware that dumps may contain:
- Bearer tokens and API keys
- Passwords and credentials
- TLS certificate paths
- Internal network topology
- Service discovery credentials
- Cloud provider credentials

Store output files securely and delete after use.

## Installation

```bash
# Clone or download the script
git clone <repo-url>
cd prometheus_extractor

# Install dependencies (optional but recommended)
pip install requests

# The script works without dependencies but uses urllib with reduced features
```

## Requirements

- Python 3.6+
- `requests` library (optional, falls back to urllib)
- Windows 10+ or Linux/macOS for terminal output
- ASCII-compatible terminal for Windows users

## License

MIT License - See LICENSE file for details

## Author

Security Research & Infrastructure Tooling

## Contributing

Contributions welcome! Please submit issues and pull requests on GitHub.

## Changelog

### v2.0.0 (Latest)
- Added HTML report generation with CSS styling
- Added `--full-output` flag for complete config/target dumps
- Added full URL display in all output sections
- Improved Windows compatibility (ASCII-only output)
- Added actionable recommendations section
- Enhanced security checks for cloud service discovery
- Added direct URLs for all debug endpoints
- Improved Kubernetes enumeration
- Added performance warnings and indicators

### v1.0.0
- Initial release with basic metrics parsing
- API enumeration support
- Target and service discovery
- Rules and alerts extraction
- Security checks (pprof, config API, federation)

---

## Security-Relevant Data It Hunts

```text
Internal/private IP addresses
Hostnames
FQDNs
Domain names
OS versions
Kernel versions
Go versions
Mounted filesystems
Docker paths
Kubernetes objects
Service accounts
Secret metric names/labels
Systemd services
Windows services
Network interfaces
Routes
BIOS/vendor/hypervisor hints
CPU/memory/disk layout
Cloud/application exporter indicators
pprof exposure
```

---

## Grep One-Liners

```bash
grep -iE 'password|passwd|secret|token|apikey|api_key|client_secret|bearer|jwt|cookie|credential' metrics.txt
```

```bash
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' metrics.txt | sort -u
```

```bash
grep -iE 'kube|docker|container|namespace|serviceaccount|secret' metrics.txt
```

```bash
grep -iE 'hostname|domain|fqdn|uname|os_info|dmi|bios' metrics.txt
```

```bash
grep -iE 'route|gateway|network|interface|netstat|sockstat' metrics.txt
```
