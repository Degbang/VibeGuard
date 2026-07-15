package com.example.vibeguard.fixtures;

/**
 * Fixture proving a class-level authorization annotation covers every
 * endpoint method that doesn't itself carry one - the common
 * "secure by default" pattern. Must NOT be flagged for CWE-284.
 */
@RolesAllowed("USER")
public class ClassLevelSecuredResource {

    @GET
    public String list() {
        return "[]";
    }

    @DELETE
    public void delete() {
    }
}
