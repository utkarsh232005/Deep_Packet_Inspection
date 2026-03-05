# DPI Engine - Deep Packet Inspection System (Java Version)

**This is the Java conversion of the original C++ DPI Engine**

An advanced, multi-threaded Deep Packet Inspection (DPI) system for analyzing, classifying, and filtering network packets in real-time.

---

## Table of Contents

1. [What is DPI?](#what-is-dpi)
2. [Project Overview](#project-overview)
3. [Architecture](#architecture)
4. [Building the Project](#building-the-project)
5. [Running the Engine](#running-the-engine)
6. [Usage Examples](#usage-examples)
7. [Configuration](#configuration)
8. [Rules and Blocking](#rules-and-blocking)
9. [Performance Tuning](#performance-tuning)
10. [Understanding the Output](#understanding-the-output)

---

## What is DPI?

**Deep Packet Inspection (DPI)** is a technology that examines the contents of network packets as they pass through a network device, not just their headers. Unlike simple firewalls that only look at source and destination IP addresses, DPI inspects the payload data inside packets.

### Real-World Applications:
- **ISPs**: Throttle or block bandwidth-heavy applications
- **Enterprises**: Block social media or non-work-related traffic on office networks
- **Parental Controls**: Filter inappropriate content
- **Security**: Detect malware and intrusion attempts
- **QoS Management**: Prioritize critical traffic

### What This DPI Engine Does:
```
Input PCAP File
      ↓
[DPI Engine Analysis]
  • Parses packets (Ethernet, IPv4, TCP, UDP)
  • Extracts SNI (Server Name Indication) from HTTPS
  • Identifies applications (YouTube, Facebook, Netflix, etc.)
  • Applies filtering rules (IP, App, Domain, Port)
  • Blocks unwanted traffic
      ↓
Output PCAP File (filtered traffic)
```

---

## Project Overview

### What's Included

**Java Source Code** - Converted from C++ with the same architecture:
- `FiveTuple.java` - Network flow identifier
- `AppType.java` - Application classification
- `Connection.java` - Flow state tracking
- `PcapReader.java` - PCAP file parsing
- `PacketParser.java` - Network packet parsing (Ethernet, IPv4, TCP, UDP)
- `RuleManager.java` - Filtering rules (IP, domain, app, port)
- `ConnectionTracker.java` - Per-flow statistics
- `SNIExtractor.java` - TLS SNI extraction for app classification
- `FastPathProcessor.java` - Packet processing worker (multi-threaded)
- `LoadBalancer.java` - Distributes packets to processors
- `DPIEngine.java` - Main orchestrator
- `DPIEngineMain.java` - Command-line entry point

---

## Architecture

### Multi-Threading Design

```
Input PCAP File
      ↓
[Reader Thread] → Packet Queue
                      ↓
            [Load Balancer #1]  [Load Balancer #2]
                    ↓                  ↓
           [FP#0] [FP#1]      [FP#2] [FP#3]
               ↓       ↓       ↓       ↓
               └───────┴───────┴───────┘
                       ↓
                 Output Queue
                       ↓
              [Writer Thread] → Output PCAP
```

### Key Components:

1. **Load Balancers**: Distribute packets based on consistent hashing of the FiveTuple
2. **FastPath Processors**: Process individual packets, classify applications, apply rules
3. **Connection Tracker**: Per-FP tracking of flows and statistics
4. **Rule Manager**: Thread-safe management of blocking rules

### Why Multi-Threading?

- **Parallelism**: Multiple packets processed simultaneously
- **Scalability**: Add more LBs/FPs for better throughput
- **Consistency**: Same flow always routed to same FP (proper TCP/UDP tracking)

---

## Building the Project

### Prerequisites

- **Java 11** or higher
- **Maven 3.6** or higher
- PCAP capture file (`.pcap` format)

### Build Steps

```bash
# Clone or navigate to the project directory
cd ~/Code\ Files/Packet_analyzer

# Build the project
mvn clean package

# This creates:
# - target/packet-analyzer-1.0.0.jar (standard JAR)
# - target/packet-analyzer-1.0.0-jar-with-dependencies.jar (fat JAR with dependencies)
```

### Verify Build

```bash
# Check if JAR was created
ls -la target/packet-analyzer-1.0.0.jar

# Test JAR is executable
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar com.dpi.engine.DPIEngineMain -h
```

---

## Running the Engine

### Basic Syntax

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain <input.pcap> <output.pcap> [options]
```

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `<input.pcap>` | Input PCAP file path |
| `<output.pcap>` | Output PCAP file path (filtered packets) |
| `-lbs N` | Number of load balancer threads (default: 2) |
| `-fps N` | FastPath processors per load balancer (default: 2) |
| `-queue N` | Input/output queue size (default: 10000) |
| `-rules FILE` | Rules configuration file (optional) |
| `-v, --verbose` | Verbose logging output |

---

## Usage Examples

### Example 1: Basic Filtering (Default Settings)

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain sample.pcap output.pcap
```

**Expected Output:**
```
====================================
     DPI Engine v1.0 (Java)
====================================

[INFO] DPI Engine initialized: DPIEngineConfig{lbs=2, fps_per_lb=2, queue_size=10000}
[INFO] Processing: sample.pcap -> output.pcap
[INFO] Opened PCAP file: sample.pcap
[INFO] Read 1000 packets
[INFO] Finished reading 1000 packets
[INFO] Finished writing 950 packets

=== DPI Engine Report ===
Total packets read: 1000

FastPath Statistics:
  FP#0: processed=250, blocked=10
  FP#1: processed=250, blocked=5
  FP#2: processed=250, blocked=8
  FP#3: processed=250, blocked=2

Total: processed=1000, blocked=25

Completed in 2.45 seconds
```

### Example 2: High-Performance Configuration (4 threads)

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain traffic.pcap filtered.pcap -lbs 2 -fps 4
```

This creates: 2 Load Balancers × 4 FastPath Processors = 8 processing threads

### Example 3: With Custom Queue Size

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain large_capture.pcap output.pcap -queue 50000
```

Use larger queues for high-throughput environments.

### Example 4: Verbose Output

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain sample.pcap output.pcap -v
```

Shows detailed logs for debugging.

---

## Configuration

### Programmatic Configuration (Java Code)

Create your own Java application to control the engine:

```java
import com.dpi.engine.DPIEngine;

public class MyDPIApp {
    public static void main(String[] args) {
        // Create configuration
        DPIEngine.Config config = new DPIEngine.Config();
        config.numLoadBalancers = 4;      // 4 load balancers
        config.fpsPerLb = 4;              // 4 FastPath per LB = 16 total
        config.queueSize = 50000;         // Large queues
        config.verbose = true;
        
        // Create engine
        DPIEngine engine = new DPIEngine(config);
        
        // Add blocking rules
        engine.blockIP("192.168.1.100");
        engine.blockApp("YOUTUBE");
        engine.blockDomain("facebook.com");
        engine.blockDomain("*.tiktok.com");  // Wildcard support
        
        // Process file
        boolean success = engine.processFile("input.pcap", "output.pcap");
        
        // View report
        if (success) {
            System.out.println(engine.generateReport());
        }
    }
}
```

Compile and run:
```bash
javac -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar MyDPIApp.java
java -cp .:target/packet-analyzer-1.0.0-jar-with-dependencies.jar MyDPIApp
```

---

## Rules and Blocking

The DPI engine supports four types of blocking rules:

### 1. IP-Based Blocking

Block all traffic from a specific source IP:

```java
engine.blockIP("192.168.1.50");
engine.blockIP("10.0.0.1");
```

### 2. Application-Based Blocking

Block specific applications (detected via SNI):

```java
engine.blockApp("YOUTUBE");
engine.blockApp("NETFLIX");
engine.blockApp("FACEBOOK");
engine.blockApp("TIKTOK");
```

**Supported Applications:**
- `GOOGLE` - Google services
- `FACEBOOK` - Facebook/Meta
- `YOUTUBE` - YouTube
- `TWITTER` - Twitter/X
- `INSTAGRAM` - Instagram
- `NETFLIX` - Netflix
- `AMAZON` - Amazon
- `MICROSOFT` - Microsoft services
- `APPLE` - Apple services
- `WHATSAPP` - WhatsApp
- `TELEGRAM` - Telegram
- `TIKTOK` - TikTok
- `SPOTIFY` - Spotify
- `ZOOM` - Zoom
- `DISCORD` - Discord
- `GITHUB` - GitHub
- `CLOUDFLARE` - Cloudflare

### 3. Domain-Based Blocking

Block traffic to specific domains (supports wildcards):

```java
engine.blockDomain("facebook.com");
engine.blockDomain("*.tiktok.com");           // All TikTok subdomains
engine.blockDomain("*.video.douyin.com");     // All douyin video subdomains
```

### 4. Port-Based Blocking

Block traffic to specific destination ports:

```java
RuleManager rm = engine.getRuleManager();
rm.blockPort(8080);  // Block HTTP Alternate port
rm.blockPort(3389);  // Block RDP
```

### How Blocking Works

When a packet arrives:
1. Extract the 5-tuple (src IP, dst IP, src port, dst port, protocol)
2. Check if source IP is blocked → DROP
3. Check if application is blocked → DROP
4. Check if domain (SNI) is blocked → DROP
5. Check if destination port is blocked → DROP
6. If no rules match → FORWARD to output

---

## Performance Tuning

### Thread Configuration

For different scenarios:

```
Light Traffic (< 1000 pps):     -lbs 1 -fps 2  (2 threads)
Medium Traffic (1K-10K pps):    -lbs 2 -fps 4  (8 threads) 
Heavy Traffic (10K-100K pps):   -lbs 4 -fps 4  (16 threads)
Extreme Traffic (> 100K pps):   -lbs 8 -fps 8  (64 threads)
```

**pps** = packets per second

### Queue Size Tuning

```
Bursty Traffic:     -queue 50000   (handle spikes)
Smooth Traffic:     -queue 10000   (default)
Low Memory:         -queue 5000    (constrained systems)
```

### Memory Requirements

Approximate memory usage:

```
Base:                ~100 MB
Per 1000 connections: ~50 MB
Per 10000 queue size: ~10 MB
```

Example: 2 LBs, 4 FPs, 10K queue, 10K flows:
- Base load: ~100 MB
- Queue memory: 2 × 4 × 10MB = ~80 MB
- Connection memory: ~500 MB
- Total estimate: ~700 MB

---

## Understanding the Output

### Output PCAP File

The `output.pcap` contains only the packets that passed the rules (not blocked).

View with Wireshark:
```bash
open -a Wireshark output.pcap
```

Or analyze with tshark:
```bash
tshark -r output.pcap | head -20
```

### Statistics Report

The engine prints a report with:
- **Total packets read**: All packets from input
- **Packets processed**: Packets that passed through FP threads
- **Packets blocked**: Packets dropped by rules
- **Per-FP statistics**: Load distribution across processors
- **Active rules**: IPs, domains, apps being blocked

Example:
```
=== DPI Engine Report ===
Total packets read: 5000

FastPath Statistics:
  FP#0: processed=1250, blocked=25
  FP#1: processed=1250, blocked=18
  FP#2: processed=1250, blocked=22
  FP#3: processed=1250, blocked=15

Total: processed=5000, blocked=80

Blocked Rules:
  IPs: [192.168.1.100, 10.0.0.50]
  Domains: [facebook.com, *.tiktok.com]
  Apps: [YOUTUBE, NETFLIX]
```

---

## Common Issues & Troubleshooting

### Issue: OutOfMemoryError

**Solution**: Increase JVM heap size
```bash
java -Xmx2g -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain input.pcap output.pcap
```

### Issue: File not found error

**Solution**: Use absolute paths or check file exists
```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain /full/path/to/input.pcap /full/path/to/output.pcap
```

### Issue: Slow processing

**Solution**: Increase threads and queue size
```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain input.pcap output.pcap -lbs 4 -fps 8 -queue 50000
```

### Issue: Java not found

**Solution**: Install Java 11 or higher
```bash
# macOS with Homebrew
brew install java11

# Or download from: https://www.oracle.com/java/technologies/downloads/
```

---

## Project Structure

```
Packet_analyzer/
├── pom.xml                                # Maven configuration
├── README.md                              # This file
├── test_dpi.pcap                         # Sample PCAP file for testing
├── generate_test_pcap.py                 # Script to generate test data
├── WINDOWS_SETUP.md                      # Windows-specific notes
└── src/
    ├── main/java/com/dpi/
    │   ├── engine/
    │   │   ├── DPIEngine.java            # Main orchestrator
    │   │   └── DPIEngineMain.java        # CLI entry point
    │   ├── packet/
    │   │   ├── EtherType.java            # Ethernet types
    │   │   ├── ParsedPacket.java         # Parsed packet structure
    │   │   ├── PcapReader.java           # PCAP file reader
    │   │   ├── PacketParser.java         # Packet parsing logic
    │   │   ├── Protocol.java             # Protocol constants
    │   │   ├── RawPacket.java            # Raw packet from file
    │   │   ├── TCPFlags.java             # TCP flag constants
    │   │   └── EtherType.java
    │   ├── rules/
    │   │   └── RuleManager.java          # Blocking rules management
    │   ├── threading/
    │   │   ├── ConnectionTracker.java    # Per-FP connection tracking
    │   │   ├── FastPathProcessor.java    # Worker thread
    │   │   ├── LoadBalancer.java         # Load balancing thread
    │   │   └── PacketJob.java            # Packet for threading
    │   ├── types/
    │   │   ├── AppType.java              # Application types
    │   │   ├── Connection.java           # Connection state
    │   │   ├── ConnectionState.java      # Connection states
    │   │   ├── FiveTuple.java            # Flow identifier
    │   │   └── PacketAction.java         # Packet actions
    │   └── utils/
    │       ├── SNIExtractor.java         # TLS SNI extraction
    │       └── ThreadSafeQueue.java      # Thread-safe queue
    └── test/java/com/dpi/               # Unit tests
```

---

## Differences from C++ Version

The Java version maintains the same architecture but with Java idioms:

| C++ | Java |
|-----|------|
| `std::thread` | `Thread` / `ExecutorService` |
| `std::unordered_map` | `HashMap` |
| `std::unordered_set` | `HashSet` |
| `std::shared_mutex` | `ReentrantReadWriteLock` |
| `std::optional` | `Optional` |
| `uint32_t, uint16_t` | `long`, `int` (with masking) |

---

## License & Credits

Java conversion of the original Deep Packet Inspection Engine.

---

## Support & Questions

For issues or questions:
1. Check the Troubleshooting section above
2. Review the logs with verbose mode: `-v`
3. Verify PCAP file format: `file sample.pcap`

---

**Happy packet inspecting! 🚀**
