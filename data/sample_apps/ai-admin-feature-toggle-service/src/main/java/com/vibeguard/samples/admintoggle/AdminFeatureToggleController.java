package com.vibeguard.samples.admintoggle;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admintoggle")
public class AdminFeatureToggleController {
    @GetMapping
    public ResponseEntity<?> listToggles() {
        return ResponseEntity.ok(List.of("new-checkout", "dark-mode"));
    }

    @GetMapping("/{name}")
    public ResponseEntity<?> getToggle(@PathVariable String name) {
        return ResponseEntity.ok(Map.of("name", name, "enabled", true, "rollout", 50));
    }
}
