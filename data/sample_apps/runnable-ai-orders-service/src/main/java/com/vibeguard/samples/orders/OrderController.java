package com.vibeguard.samples.orders;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Exposes authenticated HTTP endpoints for the in-memory orders store. */
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final OrderService orderService;

    /** Creates a controller backed by the supplied order service. */
    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    /** Creates an order from a validated request body. */
    @PostMapping
    public ResponseEntity<OrderResponse> create(@Valid @RequestBody CreateOrderRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(orderService.create(request));
    }

    /** Retrieves an order by its identifier. */
    @GetMapping("/{id}")
    public ResponseEntity<OrderResponse> get(@PathVariable long id) {
        OrderResponse order = orderService.get(id);
        return order == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(order);
    }
}
