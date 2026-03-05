package com.dpi.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketParser {
    private static final Logger log = LoggerFactory.getLogger(PacketParser.class);

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        try {
            if (raw.data == null || raw.data.length < 14) {
                return false;
            }

            parsed.timestampSec = raw.tsSeconds;
            parsed.timestampUsec = raw.tsMicroseconds;

            int offset = 0;

            // Ethernet Layer
            parsed.srcMac = formatMac(raw.data, offset);
            parsed.destMac = formatMac(raw.data, offset + 6);
            parsed.etherType = getUShort(raw.data, offset + 12);
            offset += 14;

            // IPv4 Layer
            if (parsed.etherType != EtherType.IPv4) {
                return true;
            }

            if (raw.data.length < offset + 20) {
                return true;
            }

            int versionIhl = raw.data[offset] & 0xFF;
            int version = (versionIhl >> 4) & 0x0F;
            int ihlWords = versionIhl & 0x0F;
            int headerLength = ihlWords * 4;

            parsed.hasIp = true;
            parsed.ipVersion = version;
            parsed.protocol = raw.data[offset + 9] & 0xFF;
            parsed.ttl = raw.data[offset + 8] & 0xFF;

            long srcIpInt = getUInt(raw.data, offset + 12);
            long destIpInt = getUInt(raw.data, offset + 16);

            parsed.srcIp = ipToString(srcIpInt);
            parsed.destIp = ipToString(destIpInt);

            offset += headerLength;

            // TCP Layer
            if (parsed.protocol == Protocol.TCP) {
                if (raw.data.length < offset + 20) {
                    return true;
                }

                parsed.hasTcp = true;
                parsed.srcPort = getUShort(raw.data, offset);
                parsed.destPort = getUShort(raw.data, offset + 2);
                parsed.seqNumber = getUInt(raw.data, offset + 4);
                parsed.ackNumber = getUInt(raw.data, offset + 8);

                int dataOffset = (raw.data[offset + 12] >> 4) & 0x0F;
                int tcpHeaderLength = dataOffset * 4;

                parsed.tcpFlags = raw.data[offset + 13] & 0xFF;

                offset += tcpHeaderLength;
            }

            // UDP Layer
            else if (parsed.protocol == Protocol.UDP) {
                if (raw.data.length < offset + 8) {
                    return true;
                }

                parsed.hasUdp = true;
                parsed.srcPort = getUShort(raw.data, offset);
                parsed.destPort = getUShort(raw.data, offset + 2);

                offset += 8;
            }

            // Payload
            if (offset < raw.data.length) {
                parsed.payloadLength = raw.data.length - offset;
                parsed.payloadData = new byte[parsed.payloadLength];
                System.arraycopy(raw.data, offset, parsed.payloadData, 0, parsed.payloadLength);
                parsed.payloadHex = bytesToHex(parsed.payloadData, Math.min(32, parsed.payloadLength));
            } else {
                parsed.payloadLength = 0;
                parsed.payloadData = new byte[0];
                parsed.payloadHex = "";
            }

            return true;
        } catch (Exception e) {
            log.warn("Error parsing packet", e);
            return false;
        }
    }

    private static String formatMac(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset] & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF,
                data[offset + 4] & 0xFF,
                data[offset + 5] & 0xFF);
    }

    private static int getUShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static long getUInt(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24) |
                ((long) (data[offset + 1] & 0xFF) << 16) |
                ((long) (data[offset + 2] & 0xFF) << 8) |
                (data[offset + 3] & 0xFF);
    }

    private static String ipToString(long ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    private static String bytesToHex(byte[] data, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02x ", data[i] & 0xFF));
        }
        return sb.toString().trim();
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Protocol.ICMP:
                return "ICMP";
            case Protocol.TCP:
                return "TCP";
            case Protocol.UDP:
                return "UDP";
            default:
                return "OTHER(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0)
            sb.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0)
            sb.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0)
            sb.append("FIN ");
        if ((flags & TCPFlags.RST) != 0)
            sb.append("RST ");
        if ((flags & TCPFlags.PSH) != 0)
            sb.append("PSH ");
        if ((flags & TCPFlags.URG) != 0)
            sb.append("URG ");
        return sb.toString().trim();
    }
}
