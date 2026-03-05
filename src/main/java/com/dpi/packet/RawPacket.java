package com.dpi.packet;

public class RawPacket {
    public int tsSeconds;
    public int tsMicroseconds;
    public int inclLength;
    public int origLength;
    public byte[] data;

    public RawPacket(int tsSeconds, int tsMicroseconds, int inclLength, int origLength, byte[] data) {
        this.tsSeconds = tsSeconds;
        this.tsMicroseconds = tsMicroseconds;
        this.inclLength = inclLength;
        this.origLength = origLength;
        this.data = data;
    }

    @Override
    public String toString() {
        return String.format("RawPacket{ts=%d.%d, len=%d, orig=%d}",
                tsSeconds, tsMicroseconds, inclLength, origLength);
    }
}
