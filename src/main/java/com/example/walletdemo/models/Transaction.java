package com.example.walletdemo.models;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "transactions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "sender_id", nullable = true) // Nullable because deposits might not have a sender
    private User sender;

    @ManyToOne
    @JoinColumn(name = "receiver_id", nullable = true) // Nullable because withdrawals might not have a receiver
    private User receiver;

    @Enumerated(EnumType.STRING)
    private TransactionType type;

    @Enumerated(EnumType.STRING)
    private TransactionStatus status;

    private Double amount;

    private LocalDateTime timestamp;

    private String description;
}
