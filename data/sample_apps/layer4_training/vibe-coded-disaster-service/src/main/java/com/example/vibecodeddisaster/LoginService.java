package com.example.vibecodeddisaster;

public class LoginService {
    public boolean authenticate(String password, String submittedPassword) {
        return password == submittedPassword;
    }
}
