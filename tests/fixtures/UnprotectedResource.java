package com.example.vibeguard.fixtures;

/**
 * Fixture with a known CWE-284 instance (an endpoint with no
 * authorization annotation), alongside negative cases that must NOT
 * be flagged: an explicit @PermitAll (a deliberate decision, not a
 * missing one), a method-level @RolesAllowed, and a plain non-endpoint
 * helper method.
 */
public class UnprotectedResource {

    @DELETE
    public void deleteAccount() {
        // no authorization annotation anywhere - CWE-284
    }

    @RolesAllowed("ADMIN")
    @POST
    public void createUser() {
    }

    @PermitAll
    @GET
    public String health() {
        return "ok";
    }

    private void internalHelper() {
        // not annotated as an endpoint at all - out of scope
    }
}
