package com.vibeguard.samples.scheduling;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scheduling")
public class ScheduleController {
    @GetMapping
    public ResponseEntity<?> listSchedules() {
        return ResponseEntity.ok(List.of("weekly-summary", "monthly-digest"));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getSchedule(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "cron", "0 0 * * MON"));
    }

    @GetMapping("/{id}/next-run")
    public ResponseEntity<?> getNextRun(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "nextRun", "2026-10-13T00:00:00Z"));
    }
}
