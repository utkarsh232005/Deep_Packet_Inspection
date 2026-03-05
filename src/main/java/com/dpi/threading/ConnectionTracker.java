package com.dpi.threading;

import com.dpi.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class ConnectionTracker {
    private static final Logger log = LoggerFactory.getLogger(ConnectionTracker.class);

    private final int fpId;
    private final long maxConnections;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Map<FiveTuple, Connection> connections = new HashMap<>();
    private long totalConnectionsSeen = 0;
    private long classified = 0;
    private long blocked = 0;

    public ConnectionTracker(int fpId) {
        this.fpId = fpId;
        this.maxConnections = 100000;
    }

    public ConnectionTracker(int fpId, long maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        lock.writeLock().lock();
        try {
            return connections.computeIfAbsent(tuple, k -> {
                totalConnectionsSeen++;
                return new Connection(tuple);
            });
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Connection getConnection(FiveTuple tuple) {
        lock.readLock().lock();
        try {
            return connections.get(tuple);
        } finally {
            lock.readLock().unlock();
        }
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        lock.writeLock().lock();
        try {
            if (isOutbound) {
                conn.packetsOut++;
                conn.bytesOut += packetSize;
            } else {
                conn.packetsIn++;
                conn.bytesIn += packetSize;
            }
            conn.lastSeen = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        lock.writeLock().lock();
        try {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classified++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void blockConnection(Connection conn) {
        lock.writeLock().lock();
        try {
            conn.state = ConnectionState.BLOCKED;
            conn.action = PacketAction.DROP;
            blocked++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void closeConnection(FiveTuple tuple) {
        lock.writeLock().lock();
        try {
            Connection conn = connections.get(tuple);
            if (conn != null) {
                conn.state = ConnectionState.CLOSED;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public int cleanupStale(long timeoutSeconds) {
        lock.writeLock().lock();
        try {
            Instant cutoff = Instant.now().minusSeconds(timeoutSeconds);
            int removed = 0;

            Iterator<Map.Entry<FiveTuple, Connection>> iter = connections.entrySet().iterator();
            while (iter.hasNext()) {
                Map.Entry<FiveTuple, Connection> entry = iter.next();
                if (entry.getValue().lastSeen.isBefore(cutoff)) {
                    iter.remove();
                    removed++;
                }
            }

            return removed;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public List<Connection> getAllConnections() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(connections.values());
        } finally {
            lock.readLock().unlock();
        }
    }

    public int getActiveCount() {
        lock.readLock().lock();
        try {
            return connections.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;

        @Override
        public String toString() {
            return String.format("TrackerStats{active=%d, total=%d, classified=%d, blocked=%d}",
                    activeConnections, totalConnectionsSeen, classifiedConnections, blockedConnections);
        }
    }

    public TrackerStats getStats() {
        lock.readLock().lock();
        try {
            TrackerStats stats = new TrackerStats();
            stats.activeConnections = connections.size();
            stats.totalConnectionsSeen = totalConnectionsSeen;
            stats.classifiedConnections = classified;
            stats.blockedConnections = blocked;
            return stats;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clear() {
        lock.writeLock().lock();
        try {
            connections.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public String toString() {
        return String.format("ConnectionTracker(FP#%d) %s", fpId, getStats());
    }
}
