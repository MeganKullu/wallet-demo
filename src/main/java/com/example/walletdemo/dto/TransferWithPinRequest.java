package com.example.walletdemo.dto;

import lombok.*;
@Setter
@Getter
public class TransferWithPinRequest extends TransferRequest {
    private String pin;
}