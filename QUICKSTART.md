Packet Analyzer - Java Implementation
====================================

**This project has been converted from C++ to Java.**

## Quick Start

```bash
# 1. Build the project
mvn clean package

# 2. Run with basic settings
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain input.pcap output.pcap

# 3. Run with custom settings (4 threads, 50K queue)
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain input.pcap output.pcap -lbs 2 -fps 4 -queue 50000
```

## What is This?

A **Deep Packet Inspection (DPI) Engine** that:
- Reads network traffic from PCAP files
- Parses packets (Ethernet, IPv4, TCP, UDP)
- Classifies applications (YouTube, Facebook, Netflix, etc.) using SNI extraction
- Applies filtering rules (block by IP, domain, application, or port)
- Writes filtered traffic to output PCAP
- Uses multi-threading for high throughput

## Key Features

✅ **Multi-threaded Architecture**
- Load Balancers distribute packets
- FastPath Processors analyze in parallel
- Consistent hashing maintains TCP/UDP state

✅ **Application Classification**
- Extracts SNI from HTTPS/TLS traffic
- Recognizes 25+ applications

✅ **Flexible Blocking Rules**
- IP-based (block source IPs)
- Application-based (block YouTube, Netflix, etc.)
- Domain-based (block facebook.com, *.tiktok.com)
- Port-based (block specific ports)

✅ **Performance Optimized**
- Configurable thread count
- Thread-safe collections
- Efficient packet processing

## Documentation

See **JAVA_README.md** for comprehensive documentation including:
- Architecture overview
- Building instructions
- Usage examples
- Configuration guide
- Performance tuning
- Troubleshooting

## Requirements

- Java 11 or higher
- Maven 3.6 or higher
- PCAP file (network capture)

## Architecture

```
Input PCAP
    ↓
[Load Balancer 1]  [Load Balancer 2]
    ↓                   ↓
[FP#0][FP#1]      [FP#2][FP#3]
    ↓                   ↓
Output PCAP
```

- **LB** = Load Balancer (distributes packets)
- **FP** = FastPath Processor (filters packets)

## Example Usage

### Block YouTube and TikTok

```bash
java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain network.pcap filtered.pcap
```

Then add rules in code:
```java
DPIEngine engine = new DPIEngine(config);
engine.blockApp("YOUTUBE");
engine.blockApp("TIKTOK");
engine.blockDomain("*.douyin.com");
engine.processFile("input.pcap", "output.pcap");
```

### High-Performance Setup (8 threads)

```bash
java -Xmx2g -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
    com.dpi.engine.DPIEngineMain large.pcap output.pcap -lbs 2 -fps 4 -queue 50000
```

## Project Structure

```
src/main/java/com/dpi/
├── engine/          # DPIEngine, main entry point
├── packet/          # PCAP reader, packet parser
├── rules/           # Rule management
├── threading/       # Load balancers, fast path processors
├── types/           # Data structures
└── utils/           # SNI extraction, thread-safe queue
```

## Statistics & Output

The engine generates a report showing:
- Total packets processed
- Packets blocked per thread
- Active filtering rules
- Processing time

## Performance Tips

| Scenario | Settings |
|----------|----------|
| Light traffic | `-lbs 1 -fps 2` |
| Medium traffic | `-lbs 2 -fps 4` |
| Heavy traffic | `-lbs 4 -fps 4` |
| Very heavy traffic | `-lbs 8 -fps 8` |

For large files: increase queue size with `-queue 50000`

## Build from Source

```bash
# Clone/navigate to project
cd Packet_analyzer

# Build
mvn clean package

# Run tests
mvn test

# Create executable JAR
mvn assembly:single
```

## Troubleshooting

**Out of Memory?**
```bash
java -Xmx2g -cp target/... com.dpi.engine.DPIEngineMain ...
```

**Slow Processing?**
```bash
# Use more threads and larger queues
-lbs 4 -fps 8 -queue 50000
```

**File not found?**
```bash
# Use absolute paths
java -cp target/... com.dpi.engine.DPIEngineMain \
    /absolute/path/input.pcap /absolute/path/output.pcap
```

---

**For detailed documentation, see JAVA_README.md**
