package com.example.vibeguard.fixtures;

/**
 * Fixture with a known CWE-20 instance (a @RequestBody endpoint
 * parameter with no @Valid/@Validated), alongside negative cases that
 * must NOT be flagged: the correctly-validated form, a @RequestBody
 * String (nothing for Bean Validation to cascade into), a
 * non-@RequestBody parameter, and a non-endpoint method.
 */
public class UnvalidatedRequestBody {

    @PostMapping("/unvalidated")
    public void unvalidated(@RequestBody OrderDto dto) {
        // missing @Valid/@Validated - CWE-20
    }

    @PostMapping("/validated")
    public void validated(@Valid @RequestBody OrderDto dto) {
        // correctly validated - must not be flagged
    }

    @PostMapping("/raw")
    public void rawBody(@RequestBody String payload) {
        // String has no bean fields to validate - must not be flagged
    }

    @GetMapping("/{id}")
    public void pathParam(@PathVariable String id) {
        // not a request body at all - must not be flagged
    }

    public void helper(OrderDto dto) {
        // not an endpoint method at all - must not be flagged
    }
}
