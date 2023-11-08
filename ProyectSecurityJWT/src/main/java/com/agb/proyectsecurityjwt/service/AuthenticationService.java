package com.agb.proyectsecurityjwt.service;

import com.agb.proyectsecurityjwt.dto.AuthenticationRequestDTO;
import com.agb.proyectsecurityjwt.dto.AuthenticationResponseDTO;
import com.agb.proyectsecurityjwt.dto.RegisterRequestDTO;
import com.agb.proyectsecurityjwt.entity.Role;
import com.agb.proyectsecurityjwt.entity.User;
import com.agb.proyectsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;

/**
 Authentication and registration operations
 */

@Service
@RequiredArgsConstructor

public class AuthenticationService {

    private Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    // Method to register a new user
    public AuthenticationResponseDTO register(RegisterRequestDTO request) {

        try {
            // Create a User object from the registration request
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword())) // Encode the password
                    .role(Role.ADMIN)// Assign the role list
                    .build();

            log.info(MessageFormat.format("**** USER WITH PREVIOUS DB REGISTRATION DATA {0}", user));

            // Save the user in the database
            userRepository.save(user);

            log.info("**** USER WITH DB REGISTRATION DATA %s".formatted(user));

            // Generate a JWT token for the registered user
            var jwtToken = jwtService.generateToken(user);

            log.info("**** Registration Successful");
            log.info(jwtToken.formatted("**** REGISTRATION TOKEN: %s"));

            // Create and return an authentication response that includes the JWT token
            return AuthenticationResponseDTO.builder()
                    .token(jwtToken)
                    .build();

        } catch (Exception ex) {

            log.error("**** Error during registration: " + ex.getMessage());
            throw ex;

        }
    }

    // Method to authenticate an existing user
    public AuthenticationResponseDTO authenticate(AuthenticationRequestDTO request) {

        try {
            // Authenticate the user's credentials using the AuthenticationManager
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // Find the user by username in the database
            var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

            // Generate a JWT token for the authenticated user
            var jwtToken = jwtService.generateToken(user);

            log.info("**** Successful authentication for user: " + user.getUsername());
            log.info(jwtToken.formatted("**** AUTHENTICATED TOKEN: %s"));

            // Create and return an authentication response that includes the JWT token
            return AuthenticationResponseDTO.builder()
                    .token(jwtToken)
                    .build();

        } catch (Exception ex) {

            log.error("**** Error during authentication: " + ex.getMessage());
            throw ex;
        }

    }
}

