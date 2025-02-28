package com.example.walletdemo.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class RegisterUserRequest {
    private String name;
    private String email;
    private String password;
    
}
