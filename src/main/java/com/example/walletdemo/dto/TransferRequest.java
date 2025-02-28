package com.example.walletdemo.dto;

import lombok.*;

@Data
@Setter
public class TransferRequest {
    private Long receiverUserId;
    private double amount;
}
