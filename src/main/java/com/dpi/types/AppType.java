package com.dpi.types;

/**
 * Application types that can be detected
 */
public enum AppType {
    UNKNOWN(0),
    HTTP(1),
    HTTPS(2),
    DNS(3),
    TLS(4),
    QUIC(5),
    GOOGLE(10),
    FACEBOOK(11),
    YOUTUBE(12),
    TWITTER(13),
    INSTAGRAM(14),
    NETFLIX(15),
    AMAZON(16),
    MICROSOFT(17),
    APPLE(18),
    WHATSAPP(19),
    TELEGRAM(20),
    TIKTOK(21),
    SPOTIFY(22),
    ZOOM(23),
    DISCORD(24),
    GITHUB(25),
    CLOUDFLARE(26);

    public final int value;

    AppType(int value) {
        this.value = value;
    }

    public static AppType fromValue(int value) {
        for (AppType app : AppType.values()) {
            if (app.value == value) {
                return app;
            }
        }
        return UNKNOWN;
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty())
            return UNKNOWN;
        String lower = sni.toLowerCase();
        if (lower.contains("google"))
            return GOOGLE;
        if (lower.contains("facebook") || lower.contains("fb.com"))
            return FACEBOOK;
        if (lower.contains("youtube"))
            return YOUTUBE;
        if (lower.contains("twitter"))
            return TWITTER;
        if (lower.contains("instagram"))
            return INSTAGRAM;
        if (lower.contains("netflix"))
            return NETFLIX;
        if (lower.contains("amazon"))
            return AMAZON;
        if (lower.contains("microsoft"))
            return MICROSOFT;
        if (lower.contains("apple"))
            return APPLE;
        if (lower.contains("whatsapp"))
            return WHATSAPP;
        if (lower.contains("telegram"))
            return TELEGRAM;
        if (lower.contains("tiktok"))
            return TIKTOK;
        if (lower.contains("spotify"))
            return SPOTIFY;
        if (lower.contains("zoom"))
            return ZOOM;
        if (lower.contains("discord"))
            return DISCORD;
        if (lower.contains("github"))
            return GITHUB;
        if (lower.contains("cloudflare"))
            return CLOUDFLARE;
        return UNKNOWN;
    }
}
