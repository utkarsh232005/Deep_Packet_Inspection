#!/usr/bin/env bash
# Build and run the DPI Engine Java Project

set -e

echo "======================================"
echo "  DPI Engine - Java Build & Run"
echo "======================================"
echo ""

# Check Java
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install Java 11 or higher"
    exit 1
fi

echo "✅ Java found:"
java -version
echo ""

# Check Maven
if ! command -v mvn &> /dev/null; then
    echo "⚠️  Maven not found. Installing with Homebrew..."
    brew install maven
fi

echo "✅ Maven found:"
mvn --version
echo ""

# Build
echo "🔨 Building DPI Engine..."
mvn clean package -DskipTests

echo ""
echo "✅ Build successful!"
echo ""
echo "JAR files created:"
ls -lh target/*.jar | awk '{print "   - " $NF " (" $5 ")"}'
echo ""

# Run example
if [ -f "test_dpi.pcap" ]; then
    echo "🚀 Running example with test_dpi.pcap..."
    java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar \
        com.dpi.engine.DPIEngineMain test_dpi.pcap example_output.pcap
    
    echo ""
    echo "✅ Output written to: example_output.pcap"
else
    echo "💡 To run: java -cp target/packet-analyzer-1.0.0-jar-with-dependencies.jar com.dpi.engine.DPIEngineMain <input.pcap> <output.pcap>"
fi

echo ""
echo "✅ Done!"
