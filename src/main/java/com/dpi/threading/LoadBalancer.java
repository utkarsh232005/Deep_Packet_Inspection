package com.dpi.threading;

import com.dpi.types.FiveTuple;
import com.dpi.utils.ThreadSafeQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.List;

public class LoadBalancer implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(LoadBalancer.class);

    private final int lbId;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private volatile boolean running = false;
    private long packetsDistributed = 0;

    public LoadBalancer(int lbId,
            List<ThreadSafeQueue<PacketJob>> fpQueues,
            ThreadSafeQueue<PacketJob> inputQueue,
            ThreadSafeQueue<PacketJob> outputQueue) {
        this.lbId = lbId;
        this.fpQueues = fpQueues;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
    }

    @Override
    public void run() {
        running = true;
        log.info("LoadBalancer[{}] started (managing {} FastPath queues)", lbId, fpQueues.size());

        while (running) {
            try {
                PacketJob job = inputQueue.dequeue();
                if (job == null)
                    break;

                int fpIndex = selectFastPath(job.tuple);
                fpQueues.get(fpIndex).enqueue(job);
                packetsDistributed++;

            } catch (InterruptedException e) {
                break;
            }
        }

        log.info("LoadBalancer[{}] stopped (distributed={})", lbId, packetsDistributed);
    }

    private int selectFastPath(FiveTuple tuple) {
        long hash = tuple.srcIp;
        hash = hash * 31 + tuple.dstIp;
        hash = hash * 31 + tuple.srcPort;
        hash = hash * 31 + tuple.dstPort;
        hash = hash * 31 + tuple.protocol;

        return (int) (Math.abs(hash) % fpQueues.size());
    }

    public void shutdown() {
        running = false;
    }

    public long getPacketsDistributed() {
        return packetsDistributed;
    }
}
