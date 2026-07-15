package com.example.vibeguard.fixtures;

/**
 * Fixture proving CWE-284 detection reaches methods inside a nested
 * class, not just top-level classes. Layer 1's flattened ParsedFile.
 * classes summary only represents top-level types, so a rule relying
 * on that summary alone would miss this entirely - a real false
 * negative found during adversarial testing.
 */
public class NestedResource {

    public static class InnerResource {

        @DELETE
        public void deleteAll() {
            // no authorization annotation - CWE-284, must still be found
        }

        @RolesAllowed("ADMIN")
        @POST
        public void create() {
            // protected at the method level - must not be flagged
        }
    }

    @RolesAllowed("ADMIN")
    public static class ProtectedInner {

        @DELETE
        public void deleteAll() {
            // covered by this (its own) class-level annotation - must not be flagged
        }
    }
}
