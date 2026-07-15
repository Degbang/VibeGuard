package com.example.vibeguard.fixtures;

/**
 * Fixture for CWE-798 adversarial cases: a hardcoded secret split across
 * literals, plus secret-reference names that must not be treated as secret
 * material.
 */
public class Cwe798AdversarialService {

    private String password = "hunter" + "2";
    private String secretName = "orders-db-secret";
    private String credentialRef = "prod/database";
}
