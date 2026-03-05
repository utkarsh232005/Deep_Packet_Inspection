package com.dpi.packet;

public class ParsedPacket {
    public int timestampSec;
    public int timestampUsec;

    public String srcMac;
    public String destMac;
    public int etherType;

    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol;
    public int ttl;

    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;

    public long seqNumber;
    public long ackNumber;
    public int tcpFlags;

    public int payloadLength;
    public byte[] payloadData;
    public String payloadHex;

    @Override
    public String toString() {
        return String.format("ParsedPacket{%s:%d -> %s:%d, protocol=%d, payload=%d bytes}",
                srcIp, srcPort, destIp, destPort, protocol, payloadLength);
    }
}
