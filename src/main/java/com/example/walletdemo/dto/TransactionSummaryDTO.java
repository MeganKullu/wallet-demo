package com.example.walletdemo.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class TransactionSummaryDTO {
    private Double totalIn = 0.0;
    private Double totalOut = 0.0;
    private Double totalTransferred = 0.0;
    private Integer transactionCount = 0;
}