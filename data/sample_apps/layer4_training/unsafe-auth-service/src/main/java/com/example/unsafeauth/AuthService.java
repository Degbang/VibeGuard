package com.example.unsafeauth;

public class AuthService {
    public boolean authenticate(String password, String submittedPassword) {
        return password == submittedPassword;
    }
}
