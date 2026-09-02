package com.example.unvalidatedorders;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
@RolesAllowed("user")
public class OrderController {
    @PostMapping
    public String create(@RequestBody OrderRequest request) {
        return request.getOrderId();
    }
}
