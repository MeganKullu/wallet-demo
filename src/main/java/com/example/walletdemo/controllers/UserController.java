package com.example.walletdemo.controllers;


import com.example.walletdemo.dto.RegisterUserRequest;
import com.example.walletdemo.dto.SetupPinRequest;
import com.example.walletdemo.dto.UserDTO;
import com.example.walletdemo.models.User;
import com.example.walletdemo.services.JwtService;
import com.example.walletdemo.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")

public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegisterUserRequest request){
        userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("Registered successfully! Please await admin approval.");
    }

    @PostMapping("/setup-pin")
    public ResponseEntity<String> setupPin(@RequestBody SetupPinRequest request, HttpServletRequest httpRequest) {
        String token = httpRequest.getHeader("Authorization").replace("Bearer ", "");
        String email = jwtService.extractEmail(token);
        userService.setupPin(email, request.getPin());
        return ResponseEntity.ok("PIN setup successful");
    }

    @PostMapping("/verify-pin")
    public ResponseEntity<Boolean> verifyPin(@RequestBody SetupPinRequest request, HttpServletRequest httpRequest) {
        String token = httpRequest.getHeader("Authorization").replace("Bearer ", "");
        String email = jwtService.extractEmail(token);
        boolean isValid = userService.verifyPin(email, request.getPin());
        return ResponseEntity.ok(isValid);
    }

    // Add this method to your existing UserController class

    @GetMapping("/search")
    public ResponseEntity<List<UserDTO>> searchUsersByEmail(@RequestParam String email) {
        List<UserDTO> users = userService.searchUsersByEmail(email);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/check-pin-status")
    public ResponseEntity<Map<String, Boolean>> checkPinStatus(HttpServletRequest httpRequest) {
        String token = httpRequest.getHeader("Authorization").replace("Bearer ", "");
        String email = jwtService.extractEmail(token);
        User user = userService.findByEmail(email);

        Map<String, Boolean> response = new HashMap<>();
        response.put("isPinSet", user.isPinSet());

        return ResponseEntity.ok(response);
    }

}
