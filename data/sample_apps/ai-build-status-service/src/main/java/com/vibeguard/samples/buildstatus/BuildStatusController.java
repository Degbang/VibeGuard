package com.vibeguard.samples.buildstatus;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/buildstatus")
public class BuildStatusController {
    @GetMapping("/latest")
    public ResponseEntity<?> getLatestBuild() {
        return ResponseEntity.ok(Map.of("commit", "a1b2c3d", "branch", "main", "status", "passing"));
    }
}
