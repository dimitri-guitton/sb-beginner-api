package com.example.sbbeginnerapi.controller;

import com.example.sbbeginnerapi.service.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    public JwtService jwtService;

    public LoginController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/api/token")
    public String getToken(Authentication authentication) {
        String token = jwtService.generateToken(authentication);

        return token;
    }
}
