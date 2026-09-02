package com.example.cleanprofile;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/profiles")
public class ProfileController {
    @GetMapping("/me")
    @RolesAllowed("user")
    public String me() {
        return "ok";
    }
}
