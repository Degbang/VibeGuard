package com.vibeguard.samples.orders;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

/** Validated request payload for a new order. */
public record CreateOrderRequest(
        @NotBlank String productCode,
        @Positive int quantity) {
}
