package com.example.openintake;

import jakarta.validation.constraints.NotBlank;

public class IntakeRequest {
    @NotBlank
    private String reference;

    public String getReference() {
        return reference;
    }
}
