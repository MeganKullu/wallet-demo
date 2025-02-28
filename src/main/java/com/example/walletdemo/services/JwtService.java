package com.example.walletdemo.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;
import java.util.Date;

@Service
public class JwtService {

    private static final String SECRET_KEY = "nnncuhuehuiw6252356287%%3e252!";

    // Generate JWT token with email, role and expiration time (1 hour)
    public String generateToken(String email, String role) {
        return JWT.create()
                .withSubject(email)
                .withClaim("role", role)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour expiry
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }

    // Extract email from JWT
    public String extractEmail(String token) {
        return decodeToken(token).getSubject();
    }

    // Extract role from JWT
    public String extractRole(String token) {
        return decodeToken(token).getClaim("role").asString();
    }

    // Validate token
    public boolean validateToken(String token, String email) {
        return (extractEmail(token).equals(email) && !isTokenExpired(token));
    }

    // Check if token is expired
    private boolean isTokenExpired(String token) {
        return decodeToken(token).getExpiresAt().before(new Date());
    }

    // Decode JWT token
    private DecodedJWT decodeToken(String token) {
        return JWT.require(Algorithm.HMAC256(SECRET_KEY))
                .build()
                .verify(token);
    }
}