package com.vibeguard.samples.logs;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/logs")
public class LogController {
    @GetMapping("/recent")
    public ResponseEntity<?> getRecentLogs() {
        return ResponseEntity.ok(List.of("INFO starting up", "WARN slow query 1200ms"));
    }

    @GetMapping
    public ResponseEntity<?> searchLogs(@RequestParam String q) {
        return ResponseEntity.ok(List.of("match for " + q));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getLogById(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "line", "ERROR NullPointerException at Foo.java:42"));
    }
}
