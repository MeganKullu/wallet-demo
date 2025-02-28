package com.example.walletdemo.services;

import com.example.walletdemo.dto.TransferRequest;
import com.example.walletdemo.models.*;
import com.example.walletdemo.repositories.TransactionRepository;
import com.example.walletdemo.repositories.WalletRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class WalletService {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Transactional
    public void transfer(Long senderUserId, TransferRequest request) {
        Wallet senderWallet = walletRepository.findByUserId(senderUserId)
                .orElseThrow(() -> new RuntimeException("Sender wallet not found"));

        Wallet receiverWallet = walletRepository.findByUserId(request.getReceiverUserId())
                .orElseThrow(() -> new RuntimeException("Receiver wallet not found"));

        if (senderWallet.getBalance() < request.getAmount()) {
            throw new RuntimeException("Insufficient funds");
        }

        senderWallet.setBalance(senderWallet.getBalance() - request.getAmount());
        receiverWallet.setBalance(receiverWallet.getBalance() + request.getAmount());

        walletRepository.save(senderWallet);
        walletRepository.save(receiverWallet);

        // Save transaction
        Transaction transaction = new Transaction();
        transaction.setSender(senderWallet.getUser());
        transaction.setReceiver(receiverWallet.getUser());
        transaction.setType(TransactionType.TRANSFER);
        transaction.setStatus(TransactionStatus.SUCCESS);
        transaction.setAmount(request.getAmount());
        transaction.setTimestamp(LocalDateTime.now());
        transaction.setDescription("Money transferred");

        transactionRepository.save(transaction);
    }

    @Transactional
    public void deposit(Long userId, Double amount) {
        Wallet wallet = walletRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));

        wallet.setBalance(wallet.getBalance() + amount);
        walletRepository.save(wallet);

        // Save transaction
        Transaction transaction = new Transaction();
        transaction.setReceiver(wallet.getUser()); // Receiver is the user themselves
        transaction.setType(TransactionType.DEPOSIT);
        transaction.setStatus(TransactionStatus.SUCCESS);
        transaction.setAmount(amount);
        transaction.setTimestamp(LocalDateTime.now());
        transaction.setDescription("Deposit successful");

        transactionRepository.save(transaction);
    }

    @Transactional
    public void withdraw(Long userId, Double amount) {
        Wallet wallet = walletRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));

        if (wallet.getBalance() < amount) {
            throw new RuntimeException("Insufficient funds");
        }

        wallet.setBalance(wallet.getBalance() - amount);
        walletRepository.save(wallet);

        // Save transaction
        Transaction transaction = new Transaction();
        transaction.setSender(wallet.getUser()); // user themselves
        transaction.setType(TransactionType.WITHDRAWAL);
        transaction.setStatus(TransactionStatus.SUCCESS);
        transaction.setAmount(amount);
        transaction.setTimestamp(LocalDateTime.now());
        transaction.setDescription("Withdrawal successful");

        transactionRepository.save(transaction);
    }
}
