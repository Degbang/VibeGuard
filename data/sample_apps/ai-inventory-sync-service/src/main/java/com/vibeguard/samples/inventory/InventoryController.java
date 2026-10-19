package com.vibeguard.samples.inventory;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/inventory")
public class InventoryController {
    @GetMapping("/levels")
    public ResponseEntity<?> getLevels() {
        return ResponseEntity.ok(Map.of("sku-1", 42, "sku-2", 7));
    }

    @GetMapping("/{sku}")
    public ResponseEntity<?> getItem(@PathVariable String sku) {
        return ResponseEntity.ok(Map.of("sku", sku, "quantity", 42));
    }

    @GetMapping("/discrepancies")
    public ResponseEntity<?> getDiscrepancies() {
        return ResponseEntity.ok(List.of("sku-1 off by 3"));
    }
}
