package com.example.vibecodeddisaster;

import jakarta.validation.constraints.NotBlank;

public class PaymentRequest {
    @NotBlank
    private String reference;

    public String getReference() {
        return reference;
    }
}
