package com.dpi.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DPIEngineMain {
    private static final Logger log = LoggerFactory.getLogger(DPIEngineMain.class);

    public static void main(String[] args) {
        printBanner();

        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine.Config config = new DPIEngine.Config();

        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "-lbs":
                    if (i + 1 < args.length) {
                        config.numLoadBalancers = Integer.parseInt(args[++i]);
                    }
                    break;
                case "-fps":
                    if (i + 1 < args.length) {
                        config.fpsPerLb = Integer.parseInt(args[++i]);
                    }
                    break;
                case "-queue":
                    if (i + 1 < args.length) {
                        config.queueSize = Integer.parseInt(args[++i]);
                    }
                    break;
                case "-rules":
                    if (i + 1 < args.length) {
                        config.rulesFile = args[++i];
                    }
                    break;
                case "-v":
                case "--verbose":
                    config.verbose = true;
                    break;
            }
        }

        log.info("Configuration: {}", config);

        try {
            DPIEngine engine = new DPIEngine(config);

            long startTime = System.currentTimeMillis();
            boolean success = engine.processFile(inputFile, outputFile);
            long elapsed = System.currentTimeMillis() - startTime;

            if (success) {
                System.out.println(engine.generateReport());
                System.out.println("\nCompleted in " + (elapsed / 1000.0) + " seconds");
                System.exit(0);
            } else {
                System.err.println("Processing failed");
                System.exit(1);
            }
        } catch (Exception e) {
            log.error("Fatal error", e);
            System.exit(1);
        }
    }

    private static void printBanner() {
        System.out.println("====================================");
        System.out.println("     DPI Engine v1.0 (Java)");
        System.out.println("====================================");
        System.out.println();
    }

    private static void printUsage() {
        System.out.println(
                "Usage: java -cp packet-analyzer.jar com.dpi.engine.DPIEngineMain <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  input.pcap   - Input PCAP file");
        System.out.println("  output.pcap  - Output PCAP file (filtered packets)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -lbs N       - Number of load balancers (default: 2)");
        System.out.println("  -fps N       - FastPath processors per LB (default: 2)");
        System.out.println("  -queue N     - Queue size (default: 10000)");
        System.out.println("  -rules FILE  - Rules configuration file");
        System.out.println("  -v, --verbose - Verbose output");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -cp packet-analyzer.jar com.dpi.engine.DPIEngineMain input.pcap output.pcap");
        System.out.println(
                "  java -cp packet-analyzer.jar com.dpi.engine.DPIEngineMain input.pcap output.pcap -lbs 4 -fps 4");
    }
}
