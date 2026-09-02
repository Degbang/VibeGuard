package com.example.unvalidatedcustomers;

import jakarta.validation.constraints.Email;

public class CustomerRequest {
    @Email
    private String email;

    public String getCustomerId() {
        return email;
    }
}
