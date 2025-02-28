package com.example.walletdemo.dto;

import com.example.walletdemo.models.Transaction;
import lombok.*;


import java.time.LocalDateTime;

@Getter
@Setter
public class TransactionDTO {
    private Long id;
    private String type;
    private Double amount;
    private String timestamp;
    private String status;
    private String description;
    private Long senderId;
    private String senderName;
    private String senderEmail;
    private Long receiverId;
    private String receiverName;
    private String receiverEmail;

    // Transaction direction (credit/debit)
    private String direction;

    public TransactionDTO(Transaction transaction) {
        this.id = transaction.getId();
        this.type = transaction.getType().toString();
        this.amount = transaction.getAmount();
        this.timestamp = transaction.getTimestamp().toString();
        this.status = transaction.getStatus().toString();
        this.description = transaction.getDescription();

        if (transaction.getSender() != null) {
            this.senderId = transaction.getSender().getId();
            this.senderName = transaction.getSender().getName();
            this.senderEmail = transaction.getSender().getEmail();
        }

        if (transaction.getReceiver() != null) {
            this.receiverId = transaction.getReceiver().getId();
            this.receiverName = transaction.getReceiver().getName();
            this.receiverEmail = transaction.getReceiver().getEmail();
        }

        // Set default direction based on transaction type
        this.direction = determineDirection(transaction);
    }

    private String determineDirection(Transaction transaction) {
        if (transaction.getType().toString().equals("DEPOSIT")) {
            return "CREDIT"; // Money coming into the system
        } else if (transaction.getType().toString().equals("WITHDRAWAL")) {
            return "DEBIT"; // Money leaving the system
        } else {
            return "TRANSFER"; // Money moving within the system
        }
    }

    public void setDirectionForUser(Long userId) {
        if (senderId != null && senderId.equals(userId)) {
            this.direction = "DEBIT"; // User sent money
        } else if (receiverId != null && receiverId.equals(userId)) {
            this.direction = "CREDIT"; // User received money
        }
    }
}