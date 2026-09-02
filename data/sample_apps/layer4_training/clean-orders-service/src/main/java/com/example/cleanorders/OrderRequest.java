package com.example.cleanorders;

import jakarta.validation.constraints.NotBlank;

public class OrderRequest {
    @NotBlank
    private String orderId;

    public String getOrderId() {
        return orderId;
    }
}
