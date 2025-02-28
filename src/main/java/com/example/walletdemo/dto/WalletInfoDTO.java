package com.example.walletdemo.dto;

import com.example.walletdemo.models.Transaction;
import com.example.walletdemo.models.Wallet;
import lombok.*;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
public class WalletInfoDTO {
    private Double balance;
    private List<TransactionDTO> transactions;

    public WalletInfoDTO(Wallet wallet, List<Transaction> transactions) {
        this.balance = wallet.getBalance();
        this.transactions = transactions.stream()
                .map(TransactionDTO::new)
                .collect(Collectors.toList());
    }
}