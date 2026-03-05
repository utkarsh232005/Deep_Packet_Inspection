
/**
 * DPI Engine - Deep Packet Inspection System
 * Single-file version: run with  java DPIEngineMain.java <input.pcap> <output.pcap>
 */

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────
public class DPIEngineMain {
    private static final Logger log = Logger.getLogger(DPIEngineMain.class.getName());

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
                    if (i + 1 < args.length)
                        config.numLoadBalancers = Integer.parseInt(args[++i]);
                    break;
                case "-fps":
                    if (i + 1 < args.length)
                        config.fpsPerLb = Integer.parseInt(args[++i]);
                    break;
                case "-queue":
                    if (i + 1 < args.length)
                        config.queueSize = Integer.parseInt(args[++i]);
                    break;
                case "-rules":
                    if (i + 1 < args.length)
                        config.rulesFile = args[++i];
                    break;
                case "-v":
                case "--verbose":
                    config.verbose = true;
                    break;
            }
        }

        log.info("Configuration: " + config);

        try {
            DPIEngine engine = new DPIEngine(config);

            // ── Block custom IPs ──────────────────────────────────────────────
            engine.blockIP("192.168.1.100");
            engine.blockIP("10.0.0.5");

            // ── Block domains / URLs ──────────────────────────────────────────
            engine.blockDomain("utkarshpatrikar.me");
            engine.blockDomain("malware.badsite.org");
            engine.blockDomain("*.tracking.net"); // wildcard: all subdomains

            // ── Block apps ────────────────────────────────────────────────────
            // Available: GOOGLE, FACEBOOK, YOUTUBE, TWITTER, INSTAGRAM,
            // NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP,
            // TELEGRAM, TIKTOK, SPOTIFY, ZOOM, DISCORD, GITHUB
            engine.blockApp("TIKTOK");
            engine.blockApp("NETFLIX");
            // ─────────────────────────────────────────────────────────────────

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
            log.log(Level.SEVERE, "Fatal error", e);
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
        System.out.println("Usage: java DPIEngineMain.java <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  input.pcap   - Input PCAP file");
        System.out.println("  output.pcap  - Output PCAP file (filtered packets)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -lbs N        - Number of load balancers (default: 2)");
        System.out.println("  -fps N        - FastPath processors per LB (default: 2)");
        System.out.println("  -queue N      - Queue size (default: 10000)");
        System.out.println("  -rules FILE   - Rules configuration file");
        System.out.println("  -v, --verbose - Verbose output");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java DPIEngineMain.java input.pcap output.pcap");
        System.out.println("  java DPIEngineMain.java input.pcap output.pcap -lbs 4 -fps 4");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

class FiveTuple {
    public final long srcIp;
    public final long dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol;

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : "OTHER");
        return ipToString(srcIp) + ":" + srcPort + " -> " + ipToString(dstIp) + ":" + dstPort + " (" + proto + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
                srcPort == t.srcPort && dstPort == t.dstPort && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}

enum AppType {
    UNKNOWN(0), HTTP(1), HTTPS(2), DNS(3), TLS(4), QUIC(5),
    GOOGLE(10), FACEBOOK(11), YOUTUBE(12), TWITTER(13), INSTAGRAM(14),
    NETFLIX(15), AMAZON(16), MICROSOFT(17), APPLE(18), WHATSAPP(19),
    TELEGRAM(20), TIKTOK(21), SPOTIFY(22), ZOOM(23), DISCORD(24),
    GITHUB(25), CLOUDFLARE(26);

    public final int value;

    AppType(int value) {
        this.value = value;
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty())
            return UNKNOWN;
        String l = sni.toLowerCase();
        if (l.contains("google"))
            return GOOGLE;
        if (l.contains("facebook") || l.contains("fb.com"))
            return FACEBOOK;
        if (l.contains("youtube"))
            return YOUTUBE;
        if (l.contains("twitter"))
            return TWITTER;
        if (l.contains("instagram"))
            return INSTAGRAM;
        if (l.contains("netflix"))
            return NETFLIX;
        if (l.contains("amazon"))
            return AMAZON;
        if (l.contains("microsoft"))
            return MICROSOFT;
        if (l.contains("apple"))
            return APPLE;
        if (l.contains("whatsapp"))
            return WHATSAPP;
        if (l.contains("telegram"))
            return TELEGRAM;
        if (l.contains("tiktok"))
            return TIKTOK;
        if (l.contains("spotify"))
            return SPOTIFY;
        if (l.contains("zoom"))
            return ZOOM;
        if (l.contains("discord"))
            return DISCORD;
        if (l.contains("github"))
            return GITHUB;
        if (l.contains("cloudflare"))
            return CLOUDFLARE;
        return UNKNOWN;
    }
}

enum ConnectionState {
    NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED
}

enum PacketAction {
    FORWARD, DROP, INSPECT, LOG_ONLY
}

class Connection {
    public FiveTuple tuple;
    public ConnectionState state;
    public AppType appType;
    public String sni;
    public long packetsIn = 0, packetsOut = 0, bytesIn = 0, bytesOut = 0;
    public Instant firstSeen, lastSeen;
    public PacketAction action;
    public boolean synSeen = false, synAckSeen = false, finSeen = false;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        this.state = ConnectionState.NEW;
        this.appType = AppType.UNKNOWN;
        this.sni = "";
        this.action = PacketAction.FORWARD;
        this.firstSeen = Instant.now();
        this.lastSeen = Instant.now();
    }

    @Override
    public String toString() {
        return "Connection{" + tuple + ", state=" + state + ", app=" + appType +
                ", pkt_in=" + packetsIn + ", pkt_out=" + packetsOut + "}";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PACKET LAYER
// ─────────────────────────────────────────────────────────────────────────────

class RawPacket {
    public int tsSeconds, tsMicroseconds, inclLength, origLength;
    public byte[] data;

    public RawPacket(int tsSeconds, int tsMicroseconds, int inclLength, int origLength, byte[] data) {
        this.tsSeconds = tsSeconds;
        this.tsMicroseconds = tsMicroseconds;
        this.inclLength = inclLength;
        this.origLength = origLength;
        this.data = data;
    }
}

class ParsedPacket {
    public int timestampSec, timestampUsec;
    public String srcMac, destMac;
    public int etherType;
    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp, destIp;
    public int protocol, ttl;
    public boolean hasTcp = false, hasUdp = false;
    public int srcPort, destPort;
    public long seqNumber, ackNumber;
    public int tcpFlags;
    public int payloadLength;
    public byte[] payloadData;
    public String payloadHex;

    @Override
    public String toString() {
        return "ParsedPacket{" + srcIp + ":" + srcPort + " -> " + destIp + ":" + destPort +
                ", protocol=" + protocol + ", payload=" + payloadLength + " bytes}";
    }
}

class PcapReader {
    private static final Logger log = Logger.getLogger(PcapReader.class.getName());
    private static final int MAGIC_LE = 0xa1b2c3d4;
    private static final int MAGIC_BE = 0xd4c3b2a1;

    private RandomAccessFile file;
    private String filename;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    public boolean open(String filename) {
        try {
            this.filename = filename;
            this.file = new RandomAccessFile(filename, "r");
            byte[] hdr = new byte[24];
            file.readFully(hdr);
            int magic = ((hdr[0] & 0xFF) << 24) | ((hdr[1] & 0xFF) << 16) |
                    ((hdr[2] & 0xFF) << 8) | (hdr[3] & 0xFF);
            if (magic == MAGIC_LE)
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            else if (magic == MAGIC_BE)
                byteOrder = ByteOrder.BIG_ENDIAN;
            else {
                log.severe("Invalid PCAP magic number");
                file.close();
                return false;
            }
            log.info("Opened PCAP: " + filename);
            return true;
        } catch (Exception e) {
            log.log(Level.SEVERE, "Failed to open: " + filename, e);
            return false;
        }
    }

    public void close() {
        try {
            if (file != null) {
                file.close();
                file = null;
            }
        } catch (IOException e) {
            log.warning("Error closing PCAP: " + e.getMessage());
        }
    }

    public boolean readNextPacket(RawPacket pkt) {
        try {
            if (file == null || file.getFilePointer() >= file.length())
                return false;
            byte[] h = new byte[16];
            if (file.read(h) < 16)
                return false;

            int tsS, tsU, incl, orig;
            if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
                tsS = le32(h, 0);
                tsU = le32(h, 4);
                incl = le32(h, 8);
                orig = le32(h, 12);
            } else {
                tsS = be32(h, 0);
                tsU = be32(h, 4);
                incl = be32(h, 8);
                orig = be32(h, 12);
            }
            byte[] data = new byte[incl];
            file.readFully(data);
            pkt.tsSeconds = tsS;
            pkt.tsMicroseconds = tsU;
            pkt.inclLength = incl;
            pkt.origLength = orig;
            pkt.data = data;
            return true;
        } catch (EOFException e) {
            return false;
        } catch (Exception e) {
            log.warning("Error reading packet: " + e.getMessage());
            return false;
        }
    }

    private static int le32(byte[] b, int off) {
        return ((b[off + 3] & 0xFF) << 24) | ((b[off + 2] & 0xFF) << 16) |
                ((b[off + 1] & 0xFF) << 8) | (b[off] & 0xFF);
    }

    private static int be32(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) |
                ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    public boolean isOpen() {
        return file != null;
    }
}

class PacketParser {
    private static final Logger log = Logger.getLogger(PacketParser.class.getName());
    private static final int IPv4 = 0x0800;
    private static final int ICMP = 1;
    private static final int TCP = 6;
    private static final int UDP = 17;
    static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10, URG = 0x20;

    public static boolean parse(RawPacket raw, ParsedPacket p) {
        try {
            if (raw.data == null || raw.data.length < 14)
                return false;
            p.timestampSec = raw.tsSeconds;
            p.timestampUsec = raw.tsMicroseconds;
            int off = 0;

            p.srcMac = mac(raw.data, 0);
            p.destMac = mac(raw.data, 6);
            p.etherType = us(raw.data, 12);
            off = 14;

            if (p.etherType != IPv4)
                return true;
            if (raw.data.length < off + 20)
                return true;

            int versionIhl = raw.data[off] & 0xFF;
            int ihl = (versionIhl & 0x0F) * 4;
            p.hasIp = true;
            p.ipVersion = (versionIhl >> 4) & 0x0F;
            p.protocol = raw.data[off + 9] & 0xFF;
            p.ttl = raw.data[off + 8] & 0xFF;
            p.srcIp = ipStr(ui(raw.data, off + 12));
            p.destIp = ipStr(ui(raw.data, off + 16));
            off += ihl;

            if (p.protocol == TCP) {
                if (raw.data.length < off + 20)
                    return true;
                p.hasTcp = true;
                p.srcPort = us(raw.data, off);
                p.destPort = us(raw.data, off + 2);
                p.seqNumber = ui(raw.data, off + 4);
                p.ackNumber = ui(raw.data, off + 8);
                int tcpHdrLen = ((raw.data[off + 12] >> 4) & 0x0F) * 4;
                p.tcpFlags = raw.data[off + 13] & 0xFF;
                off += tcpHdrLen;
            } else if (p.protocol == UDP) {
                if (raw.data.length < off + 8)
                    return true;
                p.hasUdp = true;
                p.srcPort = us(raw.data, off);
                p.destPort = us(raw.data, off + 2);
                off += 8;
            }

            if (off < raw.data.length) {
                p.payloadLength = raw.data.length - off;
                p.payloadData = new byte[p.payloadLength];
                System.arraycopy(raw.data, off, p.payloadData, 0, p.payloadLength);
            } else {
                p.payloadLength = 0;
                p.payloadData = new byte[0];
            }
            return true;
        } catch (Exception e) {
            log.warning("Parse error: " + e.getMessage());
            return false;
        }
    }

    private static String mac(byte[] d, int o) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                d[o] & 0xFF, d[o + 1] & 0xFF, d[o + 2] & 0xFF, d[o + 3] & 0xFF, d[o + 4] & 0xFF, d[o + 5] & 0xFF);
    }

    private static int us(byte[] d, int o) {
        return ((d[o] & 0xFF) << 8) | (d[o + 1] & 0xFF);
    }

    private static long ui(byte[] d, int o) {
        return ((long) (d[o] & 0xFF) << 24) | ((long) (d[o + 1] & 0xFF) << 16) | ((long) (d[o + 2] & 0xFF) << 8)
                | (d[o + 3] & 0xFF);
    }

    private static String ipStr(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> q;

    public ThreadSafeQueue(int capacity) {
        q = new LinkedBlockingQueue<>(capacity);
    }

    public void enqueue(T item) throws InterruptedException {
        q.put(item);
    }

    public boolean enqueueWithTimeout(T item, long timeout, TimeUnit unit) throws InterruptedException {
        return q.offer(item, timeout, unit);
    }

    public T dequeue() throws InterruptedException {
        return q.take();
    }

    public T dequeueWithTimeout(long timeout, TimeUnit unit) throws InterruptedException {
        return q.poll(timeout, unit);
    }

    public int size() {
        return q.size();
    }

    public boolean isEmpty() {
        return q.isEmpty();
    }

    public void clear() {
        q.clear();
    }
}

class SNIExtractor {
    private static final Logger log = Logger.getLogger(SNIExtractor.class.getName());

    public static String extractSNI(byte[] payload) {
        if (payload == null || payload.length < 44 || (payload[0] & 0xFF) != 0x16)
            return "";
        try {
            int off = 43;
            if (off >= payload.length)
                return "";

            int sessionLen = payload[off] & 0xFF;
            off += 1 + sessionLen;
            if (off + 2 >= payload.length)
                return "";

            int cipherLen = ((payload[off] & 0xFF) << 8) | (payload[off + 1] & 0xFF);
            off += 2 + cipherLen;
            if (off + 1 >= payload.length)
                return "";

            int comprLen = payload[off] & 0xFF;
            off += 1 + comprLen;
            if (off + 2 > payload.length)
                return "";

            int extLen = ((payload[off] & 0xFF) << 8) | (payload[off + 1] & 0xFF);
            off += 2;
            int extEnd = Math.min(off + extLen, payload.length);

            while (off + 4 <= extEnd) {
                int extType = ((payload[off] & 0xFF) << 8) | (payload[off + 1] & 0xFF);
                int eLen = ((payload[off + 2] & 0xFF) << 8) | (payload[off + 3] & 0xFF);
                off += 4;
                if (extType == 0 && off + eLen <= extEnd)
                    return parseSNIExt(payload, off, eLen);
                off += eLen;
            }
        } catch (Exception e) {
            log.fine("SNI extract failed: " + e.getMessage());
        }
        return "";
    }

    private static String parseSNIExt(byte[] p, int off, int len) {
        try {
            if (len < 5)
                return "";
            if (p[off + 2] != 0)
                return "";
            int nameLen = ((p[off + 3] & 0xFF) << 8) | (p[off + 4] & 0xFF);
            if (off + 5 + nameLen > off + len)
                return "";
            return new String(p, off + 5, nameLen, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RULES
// ─────────────────────────────────────────────────────────────────────────────

class RuleManager {
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Set<Long> blockedIPs = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<Pattern> domainPatterns = new ArrayList<>();
    private final Set<Integer> blockedPorts = new HashSet<>();

    public void blockIP(long ip) {
        wl(() -> blockedIPs.add(ip));
    }

    public void blockIP(String ip) {
        blockIP(ipToLong(ip));
    }

    public void unblockIP(long ip) {
        wl(() -> blockedIPs.remove(ip));
    }

    public boolean isIPBlocked(long ip) {
        return rl(() -> blockedIPs.contains(ip));
    }

    public List<String> getBlockedIPs() {
        return rl(() -> {
            List<String> r = new ArrayList<>();
            for (long ip : blockedIPs)
                r.add(ipStr(ip));
            return r;
        });
    }

    public void blockApp(AppType a) {
        wl(() -> blockedApps.add(a));
    }

    public void unblockApp(AppType a) {
        wl(() -> blockedApps.remove(a));
    }

    public boolean isAppBlocked(AppType a) {
        return rl(() -> blockedApps.contains(a));
    }

    public List<AppType> getBlockedApps() {
        return rl(() -> new ArrayList<>(blockedApps));
    }

    public void blockDomain(String domain) {
        wl(() -> {
            blockedDomains.add(domain);
            domainPatterns.add(Pattern.compile(domain.replace(".", "\\.").replace("*", ".*")));
        });
    }

    public void unblockDomain(String domain) {
        wl(() -> {
            blockedDomains.remove(domain);
            rebuildPatterns();
        });
    }

    public boolean isDomainBlocked(String domain) {
        return rl(() -> {
            for (Pattern p : domainPatterns)
                if (p.matcher(domain).matches())
                    return true;
            return false;
        });
    }

    public List<String> getBlockedDomains() {
        return rl(() -> new ArrayList<>(blockedDomains));
    }

    public void blockPort(int port) {
        wl(() -> blockedPorts.add(port));
    }

    public void unblockPort(int port) {
        wl(() -> blockedPorts.remove(port));
    }

    public boolean isPortBlocked(int port) {
        return rl(() -> blockedPorts.contains(port));
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
            return "BlockReason{" + type + ": " + detail + "}";
        }
    }

    public Optional<BlockReason> shouldBlock(long srcIp, int dstPort, AppType app, String sni) {
        if (isIPBlocked(srcIp))
            return Optional.of(new BlockReason(BlockReason.Type.IP, ipStr(srcIp)));
        if (isAppBlocked(app))
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.toString()));
        if (sni != null && !sni.isEmpty() && isDomainBlocked(sni))
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, sni));
        if (isPortBlocked(dstPort))
            return Optional.of(new BlockReason(BlockReason.Type.PORT, "" + dstPort));
        return Optional.empty();
    }

    public void clear() {
        wl(() -> {
            blockedIPs.clear();
            blockedApps.clear();
            blockedDomains.clear();
            domainPatterns.clear();
            blockedPorts.clear();
        });
    }

    private void rebuildPatterns() {
        domainPatterns.clear();
        for (String d : blockedDomains)
            domainPatterns.add(Pattern.compile(d.replace(".", "\\.").replace("*", ".*")));
    }

    // Helpers for locking lambdas
    private void wl(Runnable r) {
        lock.writeLock().lock();
        try {
            r.run();
        } finally {
            lock.writeLock().unlock();
        }
    }

    private <T> T rl(java.util.function.Supplier<T> s) {
        lock.readLock().lock();
        try {
            return s.get();
        } finally {
            lock.readLock().unlock();
        }
    }

    private boolean rl(java.util.function.BooleanSupplier s) {
        lock.readLock().lock();
        try {
            return s.getAsBoolean();
        } finally {
            lock.readLock().unlock();
        }
    }

    private static long ipToLong(String ip) {
        String[] p = ip.split("\\.");
        long r = 0;
        for (int i = 0; i < 4; i++)
            r = (r << 8) | (Integer.parseInt(p[i]) & 0xFF);
        return r;
    }

    private static String ipStr(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THREADING
// ─────────────────────────────────────────────────────────────────────────────

class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int payloadOffset = 0, payloadLength = 0, tcpFlags = 0;
    public byte[] payloadData;
    public long timestamp;

    public PacketJob(int packetId, FiveTuple tuple, byte[] data) {
        this.packetId = packetId;
        this.tuple = tuple;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
    }
}

class ConnectionTracker {
    private static final Logger log = Logger.getLogger(ConnectionTracker.class.getName());
    private final int fpId;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Map<FiveTuple, Connection> connections = new HashMap<>();
    private long totalSeen = 0, classified = 0, blocked = 0;

    public ConnectionTracker(int fpId) {
        this.fpId = fpId;
    }

    public Connection getOrCreateConnection(FiveTuple t) {
        lock.writeLock().lock();
        try {
            return connections.computeIfAbsent(t, k -> {
                totalSeen++;
                return new Connection(k);
            });
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void updateConnection(Connection c, int size, boolean out) {
        lock.writeLock().lock();
        try {
            if (out) {
                c.packetsOut++;
                c.bytesOut += size;
            } else {
                c.packetsIn++;
                c.bytesIn += size;
            }
            c.lastSeen = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void classifyConnection(Connection c, AppType app, String sni) {
        lock.writeLock().lock();
        try {
            c.appType = app;
            c.sni = sni;
            c.state = ConnectionState.CLASSIFIED;
            classified++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void blockConnection(Connection c) {
        lock.writeLock().lock();
        try {
            c.state = ConnectionState.BLOCKED;
            c.action = PacketAction.DROP;
            blocked++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen, classifiedConnections, blockedConnections;

        @Override
        public String toString() {
            return "TrackerStats{active=" + activeConnections + ", total=" + totalConnectionsSeen +
                    ", classified=" + classifiedConnections + ", blocked=" + blockedConnections + "}";
        }
    }

    public TrackerStats getStats() {
        lock.readLock().lock();
        try {
            TrackerStats s = new TrackerStats();
            s.activeConnections = connections.size();
            s.totalConnectionsSeen = totalSeen;
            s.classifiedConnections = classified;
            s.blockedConnections = blocked;
            return s;
        } finally {
            lock.readLock().unlock();
        }
    }
}

class FastPathProcessor implements Runnable {
    private static final Logger log = Logger.getLogger(FastPathProcessor.class.getName());
    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue, outputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private volatile boolean running = false;
    private long packetsProcessed = 0, packetsBlocked = 0;

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
        log.info("FastPath[" + fpId + "] started");
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
        log.info("FastPath[" + fpId + "] stopped (processed=" + packetsProcessed + ", blocked=" + packetsBlocked + ")");
    }

    private void processPacket(PacketJob job) {
        try {
            packetsProcessed++;
            Connection conn = connTracker.getOrCreateConnection(job.tuple);
            connTracker.updateConnection(conn, job.data.length, false);

            if (job.payloadLength > 0 && conn.state != ConnectionState.CLASSIFIED) {
                String sni = SNIExtractor.extractSNI(job.payloadData);
                if (!sni.isEmpty()) {
                    AppType app = AppType.sniToAppType(sni);
                    connTracker.classifyConnection(conn, app, sni);
                    log.fine("Classified: " + job.tuple + " -> " + app + " (SNI: " + sni + ")");
                }
            }

            RuleManager.BlockReason reason = ruleManager
                    .shouldBlock(job.tuple.srcIp, job.tuple.dstPort, conn.appType, conn.sni)
                    .orElse(null);

            if (reason != null) {
                conn.action = PacketAction.DROP;
                packetsBlocked++;
                connTracker.blockConnection(conn);
                return;
            }
            conn.action = PacketAction.FORWARD;
            outputQueue.enqueue(job);
        } catch (Exception e) {
            log.warning("Error processing packet: " + e.getMessage());
        }
    }

    public void shutdown() {
        running = false;
    }

    public long getPacketsProcessed() {
        return packetsProcessed;
    }

    public long getPacketsBlocked() {
        return packetsBlocked;
    }

    public ConnectionTracker.TrackerStats getStats() {
        return connTracker.getStats();
    }
}

class LoadBalancer implements Runnable {
    private static final Logger log = Logger.getLogger(LoadBalancer.class.getName());
    private final int lbId;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final ThreadSafeQueue<PacketJob> inputQueue, outputQueue;
    private volatile boolean running = false;
    private long distributed = 0;

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
        log.info("LoadBalancer[" + lbId + "] started (" + fpQueues.size() + " FP queues)");
        while (running) {
            try {
                PacketJob job = inputQueue.dequeue();
                if (job == null)
                    break;
                int idx = selectFP(job.tuple);
                fpQueues.get(idx).enqueue(job);
                distributed++;
            } catch (InterruptedException e) {
                break;
            }
        }
        log.info("LoadBalancer[" + lbId + "] stopped (distributed=" + distributed + ")");
    }

    private int selectFP(FiveTuple t) {
        long h = t.srcIp * 31 + t.dstIp;
        h = h * 31 + t.srcPort;
        h = h * 31 + t.dstPort;
        h = h * 31 + t.protocol;
        return (int) (Math.abs(h) % fpQueues.size());
    }

    public void shutdown() {
        running = false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE
// ─────────────────────────────────────────────────────────────────────────────

class DPIEngine {
    private static final Logger log = Logger.getLogger(DPIEngine.class.getName());

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;

        @Override
        public String toString() {
            return "Config{lbs=" + numLoadBalancers + ", fps_per_lb=" + fpsPerLb + ", queue=" + queueSize + "}";
        }
    }

    private final Config config;
    private final RuleManager ruleManager;
    private final ExecutorService executor;

    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final List<FastPathProcessor> fastPathProcessors = new ArrayList<>();
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private final AtomicInteger totalPackets = new AtomicInteger(0);

    public DPIEngine(Config config) {
        this.config = config;
        this.ruleManager = new RuleManager();
        this.inputQueue = new ThreadSafeQueue<>(config.queueSize);
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);
        int threads = config.numLoadBalancers + config.numLoadBalancers * config.fpsPerLb;
        this.executor = Executors.newFixedThreadPool(threads);
        log.info("DPI Engine initialized: " + config);
    }

    public void initialize() {
        for (int lb = 0; lb < config.numLoadBalancers; lb++) {
            List<ThreadSafeQueue<PacketJob>> fpQs = new ArrayList<>();
            for (int fp = 0; fp < config.fpsPerLb; fp++) {
                ThreadSafeQueue<PacketJob> q = new ThreadSafeQueue<>(config.queueSize);
                fpQs.add(q);
                FastPathProcessor proc = new FastPathProcessor(
                        lb * config.fpsPerLb + fp, q, outputQueue, ruleManager);
                fastPathProcessors.add(proc);
            }
            loadBalancers.add(new LoadBalancer(lb, fpQs, inputQueue, outputQueue));
        }
        log.info("Initialized: " + loadBalancers.size() + " LBs, " + fastPathProcessors.size() + " FPs");
    }

    public void start() {
        fastPathProcessors.forEach(executor::execute);
        loadBalancers.forEach(executor::execute);
        log.info("DPI Engine started");
    }

    public boolean processFile(String inputFile, String outputFile) {
        log.info("Processing: " + inputFile + " -> " + outputFile);
        try {
            initialize();
            start();

            PcapReader reader = new PcapReader();
            if (!reader.open(inputFile))
                return false;

            RawPacket raw = new RawPacket(0, 0, 0, 0, new byte[0]);
            int count = 0;
            while (reader.readNextPacket(raw)) {
                ParsedPacket parsed = new ParsedPacket();
                if (PacketParser.parse(raw, parsed)) {
                    FiveTuple tuple = new FiveTuple(
                            parseIp(parsed.srcIp), parseIp(parsed.destIp),
                            parsed.srcPort, parsed.destPort, parsed.protocol);

                    PacketJob job = new PacketJob(count, tuple, raw.data);
                    job.payloadLength = parsed.payloadLength;
                    job.payloadData = parsed.payloadData;
                    job.tcpFlags = parsed.tcpFlags;

                    inputQueue.enqueue(job);
                    totalPackets.incrementAndGet();
                    if (++count % 1000 == 0)
                        log.info("Read " + count + " packets");
                }
            }
            reader.close();
            log.info("Finished reading " + count + " packets");

            waitForCompletion();
            writeOutput(outputFile);
            stop();
            return true;
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error processing file", e);
            return false;
        }
    }

    private void waitForCompletion() {
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < 60_000) {
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
        log.warning("Timeout waiting for completion");
    }

    private void writeOutput(String filename) {
        try (RandomAccessFile raf = new RandomAccessFile(filename, "rw")) {
            ByteBuffer hdr = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            hdr.putInt(0xa1b2c3d4);
            hdr.putShort((short) 2);
            hdr.putShort((short) 4);
            hdr.putInt(0);
            hdr.putInt(0);
            hdr.putInt(65535);
            hdr.putInt(1);
            raf.write(hdr.array());

            int count = 0;
            PacketJob job;
            while ((job = outputQueue.dequeueWithTimeout(100, TimeUnit.MILLISECONDS)) != null) {
                ByteBuffer ph = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                ph.putInt((int) (job.timestamp / 1000));
                ph.putInt((int) ((job.timestamp % 1000) * 1000));
                ph.putInt(job.data.length);
                ph.putInt(job.data.length);
                raf.write(ph.array());
                raf.write(job.data);
                count++;
            }
            log.info("Wrote " + count + " packets to " + filename);
        } catch (IOException | InterruptedException e) {
            log.log(Level.SEVERE, "Error writing output", e);
            if (e instanceof InterruptedException)
                Thread.currentThread().interrupt();
        }
    }

    public void stop() {
        fastPathProcessors.forEach(FastPathProcessor::shutdown);
        loadBalancers.forEach(LoadBalancer::shutdown);
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

    public void blockDomain(String d) {
        ruleManager.blockDomain(d);
    }

    public void blockApp(String name) {
        try {
            ruleManager.blockApp(AppType.valueOf(name.toUpperCase()));
        } catch (IllegalArgumentException e) {
            log.warning("Unknown app: " + name);
        }
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== DPI Engine Report ===\n");
        sb.append("Total packets read: ").append(totalPackets.get()).append("\n");
        sb.append("\nFastPath Statistics:\n");
        long tp = 0, tb = 0;
        for (int i = 0; i < fastPathProcessors.size(); i++) {
            FastPathProcessor fp = fastPathProcessors.get(i);
            long p = fp.getPacketsProcessed(), b = fp.getPacketsBlocked();
            tp += p;
            tb += b;
            sb.append("  FP#").append(i).append(": processed=").append(p).append(", blocked=").append(b).append("\n");
        }
        sb.append("\nTotal: processed=").append(tp).append(", blocked=").append(tb).append("\n");
        sb.append("\nBlocked Rules:\n");
        sb.append("  IPs: ").append(ruleManager.getBlockedIPs()).append("\n");
        sb.append("  Domains: ").append(ruleManager.getBlockedDomains()).append("\n");
        sb.append("  Apps: ").append(ruleManager.getBlockedApps()).append("\n");
        return sb.toString();
    }

    private static long parseIp(String ip) {
        if (ip == null || ip.isEmpty())
            return 0;
        String[] p = ip.split("\\.");
        if (p.length != 4)
            return 0;
        long r = 0;
        for (int i = 0; i < 4; i++)
            r = (r << 8) | (Long.parseLong(p[i]) & 0xFF);
        return r;
    }
}
