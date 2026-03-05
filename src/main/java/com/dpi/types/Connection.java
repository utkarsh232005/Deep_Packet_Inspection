package com.dpi.types;

import java.time.Instant;

public class Connection {
    public FiveTuple tuple;
    public ConnectionState state;
    public AppType appType;
    public String sni;

    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;

    public Instant firstSeen;
    public Instant lastSeen;

    public PacketAction action;

    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

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
        return String.format("Connection{%s, state=%s, app=%s, packets_in=%d, packets_out=%d}",
                tuple, state, appType, packetsIn, packetsOut);
    }
}
