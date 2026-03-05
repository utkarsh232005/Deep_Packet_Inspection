package com.dpi.rules;

import com.dpi.types.AppType;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

public class RuleManager {
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    private Set<Long> blockedIPs = new HashSet<>();
    private Set<AppType> blockedApps = new HashSet<>();
    private Set<String> blockedDomains = new HashSet<>();
    private List<Pattern> blockedDomainPatterns = new ArrayList<>();
    private Set<Integer> blockedPorts = new HashSet<>();

    public void blockIP(long ip) {
        lock.writeLock().lock();
        try {
            blockedIPs.add(ip);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void blockIP(String ip) {
        blockIP(ipStringToLong(ip));
    }

    public void unblockIP(long ip) {
        lock.writeLock().lock();
        try {
            blockedIPs.remove(ip);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isIPBlocked(long ip) {
        lock.readLock().lock();
        try {
            return blockedIPs.contains(ip);
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        lock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (Long ip : blockedIPs) {
                result.add(ipToString(ip));
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockApp(AppType app) {
        lock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        lock.writeLock().lock();
        try {
            blockedApps.remove(app);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        lock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockDomain(String domain) {
        lock.writeLock().lock();
        try {
            blockedDomains.add(domain);
            String pattern = domainToRegex(domain);
            blockedDomainPatterns.add(Pattern.compile(pattern));
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        lock.writeLock().lock();
        try {
            blockedDomains.remove(domain);
            rebuildDomainPatterns();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        lock.readLock().lock();
        try {
            for (Pattern pattern : blockedDomainPatterns) {
                if (pattern.matcher(domain).matches()) {
                    return true;
                }
            }
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(blockedDomains);
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockPort(int port) {
        lock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        lock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        lock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            lock.readLock().unlock();
        }
    }

    public static class BlockReason {
        public enum Type {
            IP, APP, DOMAIN, PORT
        }

        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }

        @Override
        public String toString() {
            return String.format("BlockReason{%s: %s}", type, detail);
        }
    }

    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String sni) {
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, ipToString(srcIp)));
        }

        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.toString()));
        }

        if (sni != null && !sni.isEmpty() && isDomainBlocked(sni)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, sni));
        }

        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        }

        return Optional.empty();
    }

    private static long ipStringToLong(String ip) {
        String[] parts = ip.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | (Integer.parseInt(parts[i]) & 0xFF);
        }
        return result;
    }

    private static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    private String domainToRegex(String domain) {
        return domain
                .replace(".", "\\.")
                .replace("*", ".*");
    }

    private void rebuildDomainPatterns() {
        blockedDomainPatterns.clear();
        for (String domain : blockedDomains) {
            String pattern = domainToRegex(domain);
            blockedDomainPatterns.add(Pattern.compile(pattern));
        }
    }

    public void clear() {
        lock.writeLock().lock();
        try {
            blockedIPs.clear();
            blockedApps.clear();
            blockedDomains.clear();
            blockedDomainPatterns.clear();
            blockedPorts.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }
}
