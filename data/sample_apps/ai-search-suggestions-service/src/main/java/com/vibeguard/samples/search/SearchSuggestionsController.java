package com.vibeguard.samples.search;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/search")
public class SearchSuggestionsController {
    @GetMapping
    public ResponseEntity<?> getSuggestions(@RequestParam String q) {
        return ResponseEntity.ok(List.of(q + "s", q + " deals"));
    }

    @GetMapping("/popular")
    public ResponseEntity<?> getPopularSearches() {
        return ResponseEntity.ok(List.of("shoes", "laptops"));
    }
}
