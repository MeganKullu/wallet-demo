package com.example.walletdemo.services;

import com.example.walletdemo.dto.RegisterUserRequest;
import com.example.walletdemo.dto.UserDTO;
import com.example.walletdemo.models.Role;
import com.example.walletdemo.models.User;
import com.example.walletdemo.models.Wallet;
import com.example.walletdemo.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    //method to register a user
    public void registerUser(RegisterUserRequest request){
        if(userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already in use!");
        }

        // we create the user object
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        user.setApproved(false);

        // we create the wallet subsequently with a balance

        Wallet wallet = new Wallet();
        wallet.setUser(user);
        wallet.setBalance(100.0);
        user.setWallet(wallet);

        userRepository.save(user);

    }

    //method to find the user by email
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found!"));
    }

    // method to approve the user
    public void approveUser(long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found!"));
        user.setApproved(true);
        userRepository.save(user);
    }

    //method to set up pin
    public void setupPin(String email, String pin) {
        User user = findByEmail(email);
        user.setPin(passwordEncoder.encode(pin)); // Encode the PIN for security
        user.setPinSet(true);
        userRepository.save(user);
    }

    //method to verify pin
    public boolean verifyPin(String email, String pin) {
        User user = findByEmail(email);
        return passwordEncoder.matches(pin, user.getPin());
    }

    //method to get pending users
    public List<UserDTO> getPendingUsersDTO() {
        List<User> pendingUsers = userRepository.findByIsApprovedFalseAndRole(Role.USER);
        return pendingUsers.stream()
                .map(UserDTO::new)
                .collect(Collectors.toList());
    }

    //method to search user by email
    public List<UserDTO> searchUsersByEmail(String emailQuery) {
        List<User> users = userRepository.findByEmailContainingAndIsApprovedTrue(emailQuery);
        return users.stream()
                .map(UserDTO::new)
                .collect(Collectors.toList());
    }

}
