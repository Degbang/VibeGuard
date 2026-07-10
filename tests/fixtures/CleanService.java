package com.example.vibeguard.fixtures;

import java.util.List;
import java.util.Optional;

/**
 * A syntactically valid, vulnerability-free fixture used to exercise the
 * happy path of the AST parser (package, imports, class, fields, methods,
 * inheritance, interfaces, annotations).
 */
public class CleanService extends AbstractService implements Runnable, AutoCloseable {

    private final String name;
    private int retryCount, maxRetries;

    @Override
    public void run() {
        System.out.println(name);
    }

    @Override
    public void close() {
        // no-op
    }

    public Optional<String> findByName(String query, List<String> candidates) {
        return candidates.stream().filter(c -> c.equals(query)).findFirst();
    }
}
