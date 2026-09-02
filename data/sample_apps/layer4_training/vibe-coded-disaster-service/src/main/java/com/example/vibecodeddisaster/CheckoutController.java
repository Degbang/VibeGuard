package com.example.vibecodeddisaster;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/checkout")
public class CheckoutController {
    @PostMapping
    public String pay(@RequestBody PaymentRequest request) {
        return request.getReference();
    }
}
