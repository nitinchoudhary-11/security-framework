package com.dollop.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/public/hello")
    public ResponseEntity<String> publicHello() {
        return ResponseEntity.ok("Hello from public endpoint!");
    }

    @GetMapping("/protected/hello")
    public ResponseEntity<String> protectedHello() {
        return ResponseEntity.ok("Hello from protected endpoint!");
    }

    @GetMapping("/admin/hello")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminHello() {
        return ResponseEntity.ok("Hello from admin endpoint!");
    }
}
