package com.vibeguard.samples.batchexport;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/batchexport")
public class BatchExportController {
    @PostMapping("/trigger")
    public ResponseEntity<?> triggerExport() {
        String jobId = java.util.UUID.randomUUID().toString();
        return ResponseEntity.status(202).body(Map.of("jobId", jobId));
    }

    @GetMapping("/{jobId}/status")
    public ResponseEntity<?> getExportStatus(@PathVariable String jobId) {
        return ResponseEntity.ok(Map.of("jobId", jobId, "status", "running"));
    }
}
