package com.example.unvalidatedorders;

import jakarta.validation.constraints.NotBlank;

public class OrderRequest {
    @NotBlank
    private String orderId;

    public String getOrderId() {
        return orderId;
    }
}
