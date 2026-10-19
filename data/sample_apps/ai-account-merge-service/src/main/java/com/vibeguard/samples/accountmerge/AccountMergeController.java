package com.vibeguard.samples.accountmerge;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/accountmerge")
public class AccountMergeController {
    @GetMapping("/merge-preview/{sourceId}/{targetId}")
    public ResponseEntity<?> previewMerge(@PathVariable String sourceId, @PathVariable String targetId) {
        return ResponseEntity.ok(Map.of("sourceId", sourceId, "targetId", targetId, "conflicts", List.of()));
    }

    @GetMapping("/{id}/merge-history")
    public ResponseEntity<?> getMergeHistory(@PathVariable String id) {
        return ResponseEntity.ok(List.of("merged-2026-01-01"));
    }
}
