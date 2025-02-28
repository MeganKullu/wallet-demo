package com.example.walletdemo.models;


import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class User {

    public void setApproved(boolean approved) {
        this.isApproved = approved;
    }

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    private String password;

    private String pin;
    private boolean isPinSet = false;

    @Enumerated(EnumType.STRING)
    private Role role;

    private boolean isApproved = false;

    @OneToOne(mappedBy = "user", cascade =  CascadeType.ALL)
    private Wallet wallet;

    @OneToMany(mappedBy = "sender", cascade = CascadeType.ALL)
    private List<Transaction> sentTransactions;

    @OneToMany(mappedBy = "receiver", cascade = CascadeType.ALL)
    private List<Transaction> receivedTransactions;

}
