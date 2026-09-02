package com.example.openintake;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/intake")
public class IntakeController {
    @PostMapping
    public String submit(@RequestBody IntakeRequest request) {
        return request.getReference();
    }
}
