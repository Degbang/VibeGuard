package com.vibeguard.samples.replay;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/replay")
public class SessionReplayController {
    @GetMapping("/{id}/replay-events")
    public ResponseEntity<?> getReplayEvents(@PathVariable String id) {
        return ResponseEntity.ok(List.of(Map.of("type", "click", "target", "#submit"), Map.of("type", "input", "field", "email")));
    }
}
