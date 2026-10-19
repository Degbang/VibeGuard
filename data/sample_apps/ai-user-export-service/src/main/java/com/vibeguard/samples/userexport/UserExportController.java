package com.vibeguard.samples.userexport;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/userexport")
public class UserExportController {
    @GetMapping("/{id}/export")
    public ResponseEntity<?> exportUser(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "email", "user@example.com", "address", "123 Main St"));
    }

    @GetMapping("/{id}/export/status")
    public ResponseEntity<?> getExportStatus(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "status", "ready"));
    }
}
