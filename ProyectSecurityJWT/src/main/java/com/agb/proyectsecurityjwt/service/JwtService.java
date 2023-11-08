package com.agb.proyectsecurityjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * This service class is responsible for handling JSON Web Tokens (JWTs) in a Spring application.
 * It provides a set of methods to perform the following tasks:
 * - Generate JWT tokens with optional custom claims.
 * - Extract information from JWT tokens, such as the username and expiration date.
 * - Validate JWT tokens to ensure their integrity and authenticity.
 */

@Service
public class JwtService {

    // Secret key for JWT token signing
    private static final String SECRET_KEY = "GQR5L7xkKqsMkK7NDCyW/TtgLXnc7eiP0bZurbWq/USCx1qTnKJLQvPXb0IQwMqE";

    // [ Extraction methods ]

    // Get the username (subject) from the JWT token
    public String extractUserName(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    // Get the expiration date from the JWT token
    private Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }

    // Get a specific claim from the token (any claim)
    // Claims are encoded in the token body and used to convey information about the authenticated user, permissions, roles, or other relevant data
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Get all claims from the JWT token
    private Claims extractAllClaims(String token) {

        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Generate a basic token without additional claims for user information
    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);
    }

    // Generate a more elaborate token with custom additional claims
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Check if a JWT token is valid for a UserDetails user
    public boolean isTokenValid(String token, UserDetails userDetails) {

        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Check if a JWT token has expired
    private boolean isTokenExpired(String token) {

        return extractExpiration(token).before(new Date());
    }

    // Get the signing key from the secret key in Base64 format
    private Key getSignInKey() {

        // Decode the secret key
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // Create an HMAC signing key
        return Keys.hmacShaKeyFor(keyBytes);
    }
}