package com.example.walletdemo.controllers;

import com.example.walletdemo.dto.*;
import com.example.walletdemo.models.Transaction;
import com.example.walletdemo.models.User;
import com.example.walletdemo.models.Wallet;
import com.example.walletdemo.services.JwtService;
import com.example.walletdemo.services.TransactionService;
import com.example.walletdemo.services.UserService;
import com.example.walletdemo.services.WalletService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.beans.factory.annotation.Autowired;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class WalletController {

    @Autowired
    private WalletService walletService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    @Autowired
    private TransactionService transactionService;


    // Transfer by email method
    @PostMapping("/transfer-by-email")
    public ResponseEntity<String> transferByEmail(
            @RequestBody TransferByEmailRequest transferRequest,
            HttpServletRequest request
    ) {
        // Extract JWT from request header
        String token = request.getHeader("Authorization").replace("Bearer ", "");
        String senderEmail = jwtService.extractEmail(token);

        // Find sender
        User sender = userService.findByEmail(senderEmail);

        // Check if user is approved
        if (!sender.isApproved()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Account pending approval");
        }

        // Verify PIN before proceeding
        if (!userService.verifyPin(senderEmail, transferRequest.getPin())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid PIN");
        }

        // Check if PIN is set
        if (!sender.isPinSet()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("PIN not set. Please set your PIN first.");
        }

        try {
            // Find receiver by email
            User receiver = userService.findByEmail(transferRequest.getReceiverEmail());

            // Create transfer request
            TransferRequest transferReq = new TransferRequest();
            transferReq.setAmount(transferRequest.getAmount());
            transferReq.setReceiverUserId(receiver.getId());

            // Perform transfer
            walletService.transfer(sender.getId(), transferReq);

            return ResponseEntity.ok("Transfer Successful!");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // Get wallet info method
    @GetMapping("/wallet-info")
    public ResponseEntity<?> getWalletInfo(HttpServletRequest request) {
        // Extract JWT from request header
        String token = request.getHeader("Authorization").replace("Bearer ", "");
        String email = jwtService.extractEmail(token);

        // Find user and wallet
        User user = userService.findByEmail(email);

        // Check if user is approved
        if (!user.isApproved()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Account pending approval"));
        }

        Wallet wallet = user.getWallet();

        // Get user transactions
        List<Transaction> transactions = transactionService.getTransactionsByUserId(user.getId());

        // Create wallet info DTO
        WalletInfoDTO walletInfo = new WalletInfoDTO(wallet, transactions);

        // Set directions for each transaction from user's perspective
        walletInfo.getTransactions().forEach(dto -> dto.setDirectionForUser(user.getId()));

        return ResponseEntity.ok(walletInfo);
    }

    // get transaction summary
    @PostMapping("/email-transaction-summary")
    public ResponseEntity<String> emailTransactionSummary(HttpServletRequest request) {
        try {
            // Extract JWT from request header
            String token = request.getHeader("Authorization").replace("Bearer ", "");
            String email = jwtService.extractEmail(token);

            // Find user
            User user = userService.findByEmail(email);

            // Check if user is approved
            if (!user.isApproved()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Account pending approval");
            }

            // Email transaction summary directly without any approval step
            transactionService.emailTransactionSummary(user);

            return ResponseEntity.ok("Transaction summary has been emailed to your address (" + user.getEmail() + ")");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to email transaction summary: " + e.getMessage());
        }
    }

    //deposit funds
    @PostMapping("/deposit")
    public ResponseEntity<?> deposit(@RequestBody Map<String, Double> request, HttpServletRequest httpRequest) {
        try {
            String token = httpRequest.getHeader("Authorization").replace("Bearer ", "");
            String email = jwtService.extractEmail(token);
            User user = userService.findByEmail(email);

            // Check if user is approved
            if (!user.isApproved()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Account pending approval"));
            }

            Double amount = request.get("amount");
            if (amount == null || amount <= 0) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
            }

            walletService.deposit(user.getId(), amount);

            return ResponseEntity.ok(Map.of(
                    "message", "Deposit successful",
                    "amount", amount,
                    "newBalance", user.getWallet().getBalance() + amount
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }


    //withdraw funds
    @PostMapping("/withdraw")
    public ResponseEntity<?> withdraw(@RequestBody Map<String, Object> request, HttpServletRequest httpRequest) {
        try {
            String token = httpRequest.getHeader("Authorization").replace("Bearer ", "");
            String email = jwtService.extractEmail(token);
            User user = userService.findByEmail(email);

            // Check if user is approved
            if (!user.isApproved()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Account pending approval"));
            }

            // Verify PIN before proceeding
            String pin = (String) request.get("pin");
            if (pin == null || !userService.verifyPin(email, pin)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid PIN"));
            }

            // Check if PIN is set
            if (!user.isPinSet()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "PIN not set. Please set your PIN first."));
            }

            Double amount = ((Number) request.get("amount")).doubleValue();
            if (amount == null || amount <= 0) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid amount"));
            }

            // Check if user has sufficient balance
            if (user.getWallet().getBalance() < amount) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Insufficient funds"));
            }

            walletService.withdraw(user.getId(), amount);

            return ResponseEntity.ok(Map.of(
                    "message", "Withdrawal successful",
                    "amount", amount,
                    "newBalance", user.getWallet().getBalance() - amount
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }
}