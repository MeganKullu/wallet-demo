package com.example.walletdemo.controllers;

import com.example.walletdemo.dto.TransactionDTO;
import com.example.walletdemo.dto.TransactionSummaryDTO;
import com.example.walletdemo.dto.UserDTO;
import com.example.walletdemo.models.Transaction;
import com.example.walletdemo.models.User;
import com.example.walletdemo.services.TransactionService;
import com.example.walletdemo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private TransactionService transactionService;

    @PutMapping("/approve/{userId}")
    public ResponseEntity<String> approveUser(@PathVariable Long userId){
        userService.approveUser(userId);
        return ResponseEntity.ok("User approved successfully");
    }

    //get pending users
    @GetMapping("/pending-users")
    public ResponseEntity<List<UserDTO>> getPendingUsers() {
        List<UserDTO> pendingUsers = userService.getPendingUsersDTO();
        return ResponseEntity.ok(pendingUsers);
    }

    // Get all transactions
    @GetMapping("/transactions")
    public ResponseEntity<List<TransactionDTO>> getAllTransactions() {
        List<TransactionDTO> transactionDTOs = transactionService.getAllTransactionsDTO();
        return ResponseEntity.ok(transactionDTOs);
    }

    // Get transactions by user ID
    @GetMapping("/transactions/{userId}")
    public ResponseEntity<List<TransactionDTO>> getTransactionsByUserId(@PathVariable Long userId) {
        List<TransactionDTO> transactionDTOs = transactionService.getTransactionsByUserIdDTO(userId);
        return ResponseEntity.ok(transactionDTOs);
    }

    // Get transactions summary
    @GetMapping("/transactions-summary")
    public ResponseEntity<TransactionSummaryDTO> getTransactionSummary() {
        TransactionSummaryDTO summary = transactionService.getTransactionSummary();
        return ResponseEntity.ok(summary);
    }
}
