package com.dpi.types;

import java.util.Objects;
import java.util.Arrays;

/**
 * FiveTuple: Uniquely identifies a connection/flow
 * Consists of: source IP, destination IP, source port, destination port,
 * protocol
 */
public class FiveTuple {
    public final long srcIp; // 32-bit IPv4 address
    public final long dstIp; // 32-bit IPv4 address
    public final int srcPort; // 16-bit port
    public final int dstPort; // 16-bit port
    public final int protocol; // 8-bit: TCP=6, UDP=17

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /**
     * Create reverse tuple (for matching bidirectional flows)
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * Convert IP address (long) to dotted decimal string
     */
    public static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip) & 0xFF,
                (ip >> 8) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 24) & 0xFF);
    }

    @Override
    public String toString() {
        String protocolName = protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : "OTHER");
        return String.format("%s:%d -> %s:%d (%s)",
                ipToString(srcIp), srcPort,
                ipToString(dstIp), dstPort,
                protocolName);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        FiveTuple that = (FiveTuple) o;
        return srcIp == that.srcIp &&
                dstIp == that.dstIp &&
                srcPort == that.srcPort &&
                dstPort == that.dstPort &&
                protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}
