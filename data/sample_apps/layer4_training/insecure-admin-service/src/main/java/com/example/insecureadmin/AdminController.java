package com.example.insecureadmin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {
    private String apiKey = "sk-live-admin-4c1b9a";

    @GetMapping("/status")
    public String status() {
        return "admin-ok:" + apiKey.length();
    }
}
