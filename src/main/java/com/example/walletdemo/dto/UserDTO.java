package com.example.walletdemo.dto;

import com.example.walletdemo.models.Role;
import com.example.walletdemo.models.User;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor

public class UserDTO {
    private Long id;
    private String name;
    private String email;
    private Role role;
    private boolean approved;
    private boolean pinSet;
    private Double walletBalance;

    // Constructor to convert from User entity
    public UserDTO(User user) {
        this.id = user.getId();
        this.name = user.getName();
        this.email = user.getEmail();
        this.role = user.getRole();
        this.approved = user.isApproved();
        this.pinSet = user.isPinSet();
        this.walletBalance = user.getWallet() != null ? user.getWallet().getBalance() : 0.0;
    }


}