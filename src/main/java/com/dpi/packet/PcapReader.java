package com.dpi.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.nio.ByteOrder;

public class PcapReader {
    private static final Logger log = LoggerFactory.getLogger(PcapReader.class);
    private static final int MAGIC_NUMBER = 0xa1b2c3d4;
    private static final int MAGIC_NUMBER_SWAPPED = 0xd4c3b2a1;

    private RandomAccessFile file;
    private String filename;
    private boolean needsByteSwap = false;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;

    public boolean open(String filename) {
        try {
            this.filename = filename;
            this.file = new RandomAccessFile(filename, "r");
            byte[] globalHeaderBytes = new byte[24];
            file.readFully(globalHeaderBytes);

            int magic = ((globalHeaderBytes[0] & 0xFF) << 24) |
                    ((globalHeaderBytes[1] & 0xFF) << 16) |
                    ((globalHeaderBytes[2] & 0xFF) << 8) |
                    (globalHeaderBytes[3] & 0xFF);

            if (magic == MAGIC_NUMBER) {
                needsByteSwap = false;
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else if (magic == MAGIC_NUMBER_SWAPPED) {
                needsByteSwap = true;
                byteOrder = ByteOrder.BIG_ENDIAN;
            } else {
                log.error("Invalid PCAP file: bad magic number");
                file.close();
                return false;
            }
            log.info("Opened PCAP file: {}", filename);
            return true;
        } catch (Exception e) {
            log.error("Failed to open PCAP file: {}", filename, e);
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
            log.warn("Error closing PCAP file", e);
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        try {
            if (file == null || file.getFilePointer() >= file.length()) {
                return false;
            }
            byte[] headerBytes = new byte[16];
            int bytesRead = file.read(headerBytes);
            if (bytesRead < 16) {
                return false;
            }

            int tsSeconds, tsMicroseconds, inclLength, origLength;
            if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
                tsSeconds = ((headerBytes[3] & 0xFF) << 24) | ((headerBytes[2] & 0xFF) << 16) |
                        ((headerBytes[1] & 0xFF) << 8) | (headerBytes[0] & 0xFF);
                tsMicroseconds = ((headerBytes[7] & 0xFF) << 24) | ((headerBytes[6] & 0xFF) << 16) |
                        ((headerBytes[5] & 0xFF) << 8) | (headerBytes[4] & 0xFF);
                inclLength = ((headerBytes[11] & 0xFF) << 24) | ((headerBytes[10] & 0xFF) << 16) |
                        ((headerBytes[9] & 0xFF) << 8) | (headerBytes[8] & 0xFF);
                origLength = ((headerBytes[15] & 0xFF) << 24) | ((headerBytes[14] & 0xFF) << 16) |
                        ((headerBytes[13] & 0xFF) << 8) | (headerBytes[12] & 0xFF);
            } else {
                tsSeconds = ((headerBytes[0] & 0xFF) << 24) | ((headerBytes[1] & 0xFF) << 16) |
                        ((headerBytes[2] & 0xFF) << 8) | (headerBytes[3] & 0xFF);
                tsMicroseconds = ((headerBytes[4] & 0xFF) << 24) | ((headerBytes[5] & 0xFF) << 16) |
                        ((headerBytes[6] & 0xFF) << 8) | (headerBytes[7] & 0xFF);
                inclLength = ((headerBytes[8] & 0xFF) << 24) | ((headerBytes[9] & 0xFF) << 16) |
                        ((headerBytes[10] & 0xFF) << 8) | (headerBytes[11] & 0xFF);
                origLength = ((headerBytes[12] & 0xFF) << 24) | ((headerBytes[13] & 0xFF) << 16) |
                        ((headerBytes[14] & 0xFF) << 8) | (headerBytes[15] & 0xFF);
            }

            byte[] data = new byte[inclLength];
            file.readFully(data);

            packet.tsSeconds = tsSeconds;
            packet.tsMicroseconds = tsMicroseconds;
            packet.inclLength = inclLength;
            packet.origLength = origLength;
            packet.data = data;

            return true;
        } catch (EOFException e) {
            return false;
        } catch (Exception e) {
            log.warn("Error reading packet", e);
            return false;
        }
    }

    public boolean isOpen() {
        return file != null;
    }

    public String getFilename() {
        return filename;
    }
}
