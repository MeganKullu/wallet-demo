package com.example.walletdemo.dto;


import lombok.*;

@Setter
@Getter
public class LoginRequest {
    private String email;
    private String password;
}
