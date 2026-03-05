package com.dpi.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;

public class SNIExtractor {
    private static final Logger log = LoggerFactory.getLogger(SNIExtractor.class);

    public static String extractSNI(byte[] payload) {
        if (payload == null || payload.length < 44) {
            return "";
        }

        if ((payload[0] & 0xFF) != 0x16) {
            return "";
        }

        int offset = 43;

        if (offset >= payload.length) {
            return "";
        }

        try {
            int sessionIdLen = payload[offset] & 0xFF;
            offset += 1 + sessionIdLen;

            if (offset + 2 >= payload.length) {
                return "";
            }

            int cipherSuitesLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2 + cipherSuitesLen;

            if (offset + 1 >= payload.length) {
                return "";
            }

            int compressionMethodsLen = payload[offset] & 0xFF;
            offset += 1 + compressionMethodsLen;

            if (offset + 2 > payload.length) {
                return "";
            }

            int extensionsLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            offset += 2;

            int extensionsEnd = offset + extensionsLen;
            if (extensionsEnd > payload.length) {
                extensionsEnd = payload.length;
            }

            while (offset + 4 <= extensionsEnd) {
                int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                int extLen = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
                offset += 4;

                if (extType == 0 && offset + extLen <= extensionsEnd) {
                    return parseSNIExtension(payload, offset, extLen);
                }

                offset += extLen;
            }

            return "";
        } catch (Exception e) {
            log.debug("Failed to extract SNI", e);
            return "";
        }
    }

    private static String parseSNIExtension(byte[] payload, int offset, int len) {
        try {
            if (len < 5) {
                return "";
            }

            int listLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            if (offset + 2 + listLen > offset + len) {
                return "";
            }

            int nameType = payload[offset + 2] & 0xFF;
            if (nameType != 0) {
                return "";
            }

            int nameLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
            if (offset + 5 + nameLen > offset + len) {
                return "";
            }

            byte[] nameBytes = new byte[nameLen];
            System.arraycopy(payload, offset + 5, nameBytes, 0, nameLen);
            return new String(nameBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.debug("Failed to parse SNI extension", e);
            return "";
        }
    }
}
