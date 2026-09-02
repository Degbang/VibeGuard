package com.example.unvalidatedcustomers;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/customers")
@RolesAllowed("user")
public class CustomerController {
    @PostMapping
    public String create(@RequestBody CustomerRequest request) {
        return request.getCustomerId();
    }
}
