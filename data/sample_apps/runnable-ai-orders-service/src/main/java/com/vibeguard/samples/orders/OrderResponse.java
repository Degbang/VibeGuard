package com.vibeguard.samples.orders;

/** Public representation of an order held by the sample service. */
public record OrderResponse(long id, String productCode, int quantity) {
}
