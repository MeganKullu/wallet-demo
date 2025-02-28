package com.example.walletdemo.config;

import com.example.walletdemo.models.Role;
import com.example.walletdemo.models.User;
import com.example.walletdemo.models.Wallet;
import com.example.walletdemo.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AdminInitializer {

    @Bean
    public CommandLineRunner initializeAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Check if admin user already exists
            if (!userRepository.existsByEmail("kullumegan@gmail.com")) {
                // Create admin user
                User adminUser = new User();
                adminUser.setName("Administrator");
                adminUser.setEmail("kullumegan@gmail.com");
                adminUser.setPassword(passwordEncoder.encode("admin123"));
                adminUser.setRole(Role.ADMIN);
                adminUser.setApproved(true);

                userRepository.save(adminUser);

                System.out.println("Default admin user created with email: kullumegan@gmail.com and password: admin123");
            }
        };
    }
}