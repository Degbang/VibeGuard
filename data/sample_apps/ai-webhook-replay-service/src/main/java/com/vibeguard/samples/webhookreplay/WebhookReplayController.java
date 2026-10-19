package com.vibeguard.samples.webhookreplay;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/webhookreplay")
public class WebhookReplayController {
    @GetMapping("/replay/{eventId}")
    public ResponseEntity<?> replayEvent(@PathVariable String eventId) {
        return ResponseEntity.ok(Map.of("eventId", eventId, "replayed", true));
    }

    @GetMapping("/replay/{eventId}/log")
    public ResponseEntity<?> getReplayLog(@PathVariable String eventId) {
        return ResponseEntity.ok(List.of("delivered", "acked"));
    }
}
