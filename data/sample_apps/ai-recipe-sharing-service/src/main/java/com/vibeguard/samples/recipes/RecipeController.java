package com.vibeguard.samples.recipes;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/recipes")
public class RecipeController {
    @GetMapping("/public")
    public ResponseEntity<?> listPublicRecipes() {
        return ResponseEntity.ok(List.of("Pasta", "Salad"));
    }

    @GetMapping("/public/{id}")
    public ResponseEntity<?> getPublicRecipe(@PathVariable String id) {
        return ResponseEntity.ok(Map.of("id", id, "title", "Pasta", "steps", List.of("Boil", "Drain")));
    }
}
