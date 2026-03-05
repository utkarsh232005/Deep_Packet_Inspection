package com.dpi.engine;

import com.dpi.packet.*;
import com.dpi.rules.RuleManager;
import com.dpi.threading.*;
import com.dpi.types.*;
import com.dpi.utils.ThreadSafeQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class DPIEngine {
    private static final Logger log = LoggerFactory.getLogger(DPIEngine.class);

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;

        @Override
        public String toString() {
            return String.format("DPIEngineConfig{lbs=%d, fps_per_lb=%d, queue_size=%d}",
                    numLoadBalancers, fpsPerLb, queueSize);
        }
    }

    private final Config config;
    private final RuleManager ruleManager;
    private final ExecutorService executor;

    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final List<FastPathProcessor> fastPathProcessors = new ArrayList<>();
    private final List<ThreadSafeQueue<PacketJob>> lbToFpQueues = new ArrayList<>();
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ThreadSafeQueue<PacketJob> outputQueue;

    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private volatile boolean running = false;

    public DPIEngine(Config config) {
        this.config = config;
        this.ruleManager = new RuleManager();
        this.inputQueue = new ThreadSafeQueue<>(config.queueSize);
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);

        int totalThreads = config.numLoadBalancers + (config.numLoadBalancers * config.fpsPerLb);
        this.executor = Executors.newFixedThreadPool(totalThreads);

        log.info("DPI Engine initialized: {}", config);
    }

    public boolean initialize() {
        try {
            for (int lb = 0; lb < config.numLoadBalancers; lb++) {
                List<ThreadSafeQueue<PacketJob>> fpQueuesForThisLb = new ArrayList<>();

                for (int fp = 0; fp < config.fpsPerLb; fp++) {
                    ThreadSafeQueue<PacketJob> fpQueue = new ThreadSafeQueue<>(config.queueSize);
                    fpQueuesForThisLb.add(fpQueue);

                    FastPathProcessor processor = new FastPathProcessor(
                            lb * config.fpsPerLb + fp,
                            fpQueue,
                            outputQueue,
                            ruleManager);
                    fastPathProcessors.add(processor);
                }

                LoadBalancer lb_thread = new LoadBalancer(
                        lb,
                        fpQueuesForThisLb,
                        inputQueue,
                        outputQueue);
                loadBalancers.add(lb_thread);
            }

            log.info("Initialized: {} LBs, {} FPs",
                    loadBalancers.size(), fastPathProcessors.size());
            return true;
        } catch (Exception e) {
            log.error("Failed to initialize DPI Engine", e);
            return false;
        }
    }

    public void start() {
        running = true;

        for (FastPathProcessor fp : fastPathProcessors) {
            executor.execute(fp);
        }

        for (LoadBalancer lb : loadBalancers) {
            executor.execute(lb);
        }

        log.info("DPI Engine started");
    }

    public boolean processFile(String inputFile, String outputFile) {
        log.info("Processing: {} -> {}", inputFile, outputFile);

        try {
            initialize();
            start();

            PcapReader reader = new PcapReader();
            if (!reader.open(inputFile)) {
                return false;
            }

            RawPacket rawPacket = new RawPacket(0, 0, 0, 0, new byte[0]);
            int packetCount = 0;

            while (reader.readNextPacket(rawPacket)) {
                ParsedPacket parsed = new ParsedPacket();
                if (PacketParser.parse(rawPacket, parsed)) {
                    long srcIpLong = parseIp(parsed.srcIp);
                    long dstIpLong = parseIp(parsed.destIp);

                    FiveTuple tuple = new FiveTuple(
                            srcIpLong,
                            dstIpLong,
                            parsed.srcPort,
                            parsed.destPort,
                            parsed.protocol);

                    PacketJob job = new PacketJob(packetCount, tuple, rawPacket.data);
                    job.payloadLength = parsed.payloadLength;
                    job.payloadData = parsed.payloadData;
                    job.tcpFlags = parsed.tcpFlags;

                    inputQueue.enqueue(job);
                    packetCount++;
                    totalPackets.incrementAndGet();

                    if (packetCount % 1000 == 0) {
                        log.info("Read {} packets", packetCount);
                    }
                }
            }

            reader.close();
            log.info("Finished reading {} packets", packetCount);

            waitForCompletion();
            writeOutput(outputFile);

            stop();
            return true;

        } catch (Exception e) {
            log.error("Error processing file", e);
            return false;
        }
    }

    public void waitForCompletion() {
        long timeout = 60;
        long startTime = System.currentTimeMillis();

        while ((System.currentTimeMillis() - startTime) < (timeout * 1000)) {
            if (inputQueue.isEmpty() && outputQueue.isEmpty()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    break;
                }
                return;
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                break;
            }
        }

        log.warn("Timeout waiting for completion");
    }

    private void writeOutput(String filename) {
        try (RandomAccessFile raf = new RandomAccessFile(filename, "rw")) {
            ByteBuffer bb = ByteBuffer.allocate(24);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            bb.putInt(0xa1b2c3d4);
            bb.putShort((short) 2);
            bb.putShort((short) 4);
            bb.putInt(0);
            bb.putInt(0);
            bb.putInt(65535);
            bb.putInt(1);
            raf.write(bb.array());

            PacketJob job;
            int count = 0;
            while ((job = outputQueue.dequeueWithTimeout(100, TimeUnit.MILLISECONDS)) != null) {
                ByteBuffer pbh = ByteBuffer.allocate(16);
                pbh.order(ByteOrder.LITTLE_ENDIAN);
                pbh.putInt((int) (job.timestamp / 1000));
                pbh.putInt((int) ((job.timestamp % 1000) * 1000));
                pbh.putInt(job.data.length);
                pbh.putInt(job.data.length);

                raf.write(pbh.array());
                raf.write(job.data);
                count++;
            }

            log.info("Wrote {} packets to {}", count, filename);
        } catch (IOException e) {
            log.error("Error writing output file", e);
        } catch (InterruptedException e) {
            log.error("Interrupted while writing output", e);
            Thread.currentThread().interrupt();
        }
    }

    public void stop() {
        running = false;

        for (FastPathProcessor fp : fastPathProcessors) {
            fp.shutdown();
        }

        for (LoadBalancer lb : loadBalancers) {
            lb.shutdown();
        }

        executor.shutdown();
        try {
            executor.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }

        log.info("DPI Engine stopped");
    }

    public void blockIP(String ip) {
        ruleManager.blockIP(ip);
    }

    public void blockApp(String appName) {
        try {
            AppType app = AppType.valueOf(appName.toUpperCase());
            ruleManager.blockApp(app);
        } catch (IllegalArgumentException e) {
            log.warn("Unknown app: {}", appName);
        }
    }

    public void blockDomain(String domain) {
        ruleManager.blockDomain(domain);
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== DPI Engine Report ===\n");
        sb.append("Total packets read: ").append(totalPackets.get()).append("\n");
        sb.append("\nFastPath Statistics:\n");

        long totalProcessed = 0;
        long totalBlocked = 0;

        for (int i = 0; i < fastPathProcessors.size(); i++) {
            FastPathProcessor fp = fastPathProcessors.get(i);
            long p = fp.getPacketsProcessed();
            long b = fp.getPacketsBlocked();
            totalProcessed += p;
            totalBlocked += b;
            sb.append(String.format("  FP#%d: processed=%d, blocked=%d\n", i, p, b));
        }

        sb.append(String.format("\nTotal: processed=%d, blocked=%d\n", totalProcessed, totalBlocked));
        sb.append("\nBlocked Rules:\n");
        sb.append("  IPs: ").append(ruleManager.getBlockedIPs()).append("\n");
        sb.append("  Domains: ").append(ruleManager.getBlockedDomains()).append("\n");
        sb.append("  Apps: ").append(ruleManager.getBlockedApps()).append("\n");

        return sb.toString();
    }

    private long parseIp(String ip) {
        if (ip == null || ip.isEmpty())
            return 0;
        String[] parts = ip.split("\\.");
        if (parts.length != 4)
            return 0;
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | (Long.parseLong(parts[i]) & 0xFF);
        }
        return result;
    }
}
