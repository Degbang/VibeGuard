package com.vibeguard.samples.rollout;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/rollout")
public class FeatureRolloutController {
    @GetMapping("/status")
    public ResponseEntity<?> getRolloutStatus(@RequestParam String feature) {
        return ResponseEntity.ok(Map.of("feature", feature, "rolloutPercentage", 15, "targetSegment", "beta-testers"));
    }
}
