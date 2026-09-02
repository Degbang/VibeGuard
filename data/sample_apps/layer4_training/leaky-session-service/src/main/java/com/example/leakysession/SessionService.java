package com.example.leakysession;

public class SessionService {
    public boolean validate(String token, String submittedToken) {
        return token == submittedToken;
    }
}
