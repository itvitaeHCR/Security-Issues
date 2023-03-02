package com.practice.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
public class ResourceController {
    @GetMapping("/") // root
    public String home() {
        return "<h1>Home</h1>";
    }

    @GetMapping("/user")
    public String user() {
        return "<h1>User</h1>";
    }

    @GetMapping("/admin")
    public String admin() {
        return "<h1>Admin</h1>";
    }
}
