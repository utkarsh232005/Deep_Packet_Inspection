package com.dpi.threading;

import com.dpi.packet.PacketParser;
import com.dpi.rules.RuleManager;
import com.dpi.types.*;
import com.dpi.utils.SNIExtractor;
import com.dpi.utils.ThreadSafeQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FastPathProcessor implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(FastPathProcessor.class);

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private volatile boolean running = false;
    private long packetsProcessed = 0;
    private long packetsBlocked = 0;

    public FastPathProcessor(int fpId,
            ThreadSafeQueue<PacketJob> inputQueue,
            ThreadSafeQueue<PacketJob> outputQueue,
            RuleManager ruleManager) {
        this.fpId = fpId;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.ruleManager = ruleManager;
        this.connTracker = new ConnectionTracker(fpId);
    }

    @Override
    public void run() {
        running = true;
        log.info("FastPath[{}] started", fpId);

        while (running) {
            try {
                PacketJob job = inputQueue.dequeue();
                if (job == null)
                    break;

                processPacket(job);
            } catch (InterruptedException e) {
                break;
            }
        }

        log.info("FastPath[{}] stopped (processed={}, blocked={})",
                fpId, packetsProcessed, packetsBlocked);
    }

    private void processPacket(PacketJob job) {
        try {
            packetsProcessed++;

            Connection conn = connTracker.getOrCreateConnection(job.tuple);
            connTracker.updateConnection(conn, job.data.length, false);

            if (job.payloadLength > 0 && job.tcpFlags == 0x02) {
                classifyConnection(job, conn);
            }

            RuleManager.BlockReason blockReason = ruleManager
                    .shouldBlock(job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni)
                    .orElse(null);

            if (blockReason != null) {
                log.debug("Blocking packet: {} - reason: {}", job.tuple, blockReason);
                conn.action = PacketAction.DROP;
                packetsBlocked++;
                connTracker.blockConnection(conn);
                return;
            }

            conn.action = PacketAction.FORWARD;
            outputQueue.enqueue(job);

        } catch (Exception e) {
            log.warn("Error processing packet", e);
        }
    }

    private void classifyConnection(PacketJob job, Connection conn) {
        if (conn.state == ConnectionState.CLASSIFIED) {
            return;
        }

        try {
            String sni = SNIExtractor.extractSNI(job.payloadData);

            if (!sni.isEmpty()) {
                AppType appType = AppType.sniToAppType(sni);
                connTracker.classifyConnection(conn, appType, sni);
                log.debug("Classified: {} -> {} (SNI: {})",
                        job.tuple, appType, sni);
            }
        } catch (Exception e) {
            log.debug("Failed to classify connection", e);
        }
    }

    public void shutdown() {
        running = false;
    }

    public ConnectionTracker.TrackerStats getStats() {
        return connTracker.getStats();
    }

    public long getPacketsProcessed() {
        return packetsProcessed;
    }

    public long getPacketsBlocked() {
        return packetsBlocked;
    }
}
