package com.example.configsecret;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/health")
public class HealthController {
    @GetMapping
    @RolesAllowed("user")
    public String ok() {
        return "ok";
    }
}
