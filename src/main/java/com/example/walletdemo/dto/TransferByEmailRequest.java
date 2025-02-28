package com.example.walletdemo.dto;

import lombok.*;

@Data
public class TransferByEmailRequest {
    private String receiverEmail;
    private Double amount;
    private String pin;
}