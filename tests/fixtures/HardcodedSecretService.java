package com.example.vibeguard.fixtures;

/**
 * Fixture with a known CWE-798 instance (hardcoded credentials), plus
 * negative cases that must NOT be flagged: an externalized property
 * reference, an obvious placeholder, an empty value, and an unrelated
 * field name that happens to hold a string literal.
 */
public class HardcodedSecretService {

    private String apiKey = "sk-live-abc123def456";
    private String dbPassword = "${DB_PASSWORD}";
    private String secretToken = "CHANGE_ME";
    private String authToken = "";
    private String description = "Handles user lookups";

    public void connect() {
        String password = "hunter2";
        int retries = 3;
    }
}
