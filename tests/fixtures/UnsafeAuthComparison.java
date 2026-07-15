package com.example.vibeguard.fixtures;

/**
 * Fixture with a known CWE-287 instance (comparing a credential with
 * ==/!= instead of .equals()), alongside negative cases that must NOT
 * be flagged: the correct .equals() form, a null check, a numeric
 * field that happens to contain the word "password", and a boolean
 * literal comparison.
 */
public class UnsafeAuthComparison {

    public boolean unsafeCheck(String password, String input) {
        return password == input;
    }

    public boolean safeCheck(String password, String input) {
        return password.equals(input);
    }

    public boolean nullCheck(String password) {
        return password == null;
    }

    public boolean attemptLimitCheck(int passwordAttempts) {
        return passwordAttempts == 3;
    }

    public boolean flagCheck(boolean isValid) {
        return isValid == true;
    }

    private String password;

    public boolean thisQualifiedUnsafeCheck(String input) {
        return this.password == input;
    }
}
