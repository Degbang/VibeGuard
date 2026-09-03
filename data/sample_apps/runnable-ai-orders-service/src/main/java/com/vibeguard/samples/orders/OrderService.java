package com.vibeguard.samples.orders;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Service;

/** Stores orders in memory for the lifetime of the sample application. */
@Service
public class OrderService {
    private final AtomicLong nextId = new AtomicLong();
    private final Map<Long, OrderResponse> orders = new ConcurrentHashMap<>();

    /** Creates and retains an order. */
    public OrderResponse create(CreateOrderRequest request) {
        long id = nextId.incrementAndGet();
        OrderResponse order = new OrderResponse(id, request.productCode(), request.quantity());
        orders.put(id, order);
        return order;
    }

    /** Returns an order when it exists. */
    public OrderResponse get(long id) {
        return orders.get(id);
    }
}
