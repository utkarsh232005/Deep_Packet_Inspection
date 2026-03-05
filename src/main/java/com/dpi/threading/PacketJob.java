package com.dpi.threading;

import com.dpi.types.FiveTuple;

public class PacketJob {
    public int packetId;
    public FiveTuple tuple;
    public byte[] data;
    public int ethOffset = 0;
    public int ipOffset = 0;
    public int transportOffset = 0;
    public int payloadOffset = 0;
    public int payloadLength = 0;
    public int tcpFlags = 0;
    public byte[] payloadData;
    public long timestamp;

    public PacketJob(int packetId, FiveTuple tuple, byte[] data) {
        this.packetId = packetId;
        this.tuple = tuple;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
    }
}
