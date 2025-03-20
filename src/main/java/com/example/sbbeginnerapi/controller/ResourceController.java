package com.example.sbbeginnerapi.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class ResourceController {

    @GetMapping("/api/ressource")
    public ResponseEntity<Map<String, String>> getResource() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Hello, this is your resource!");

        return ResponseEntity.ok(response);
    }

}
