package com.agb.proyectsecurityjwt.controller;

import com.agb.proyectsecurityjwt.dto.AuthenticationRequestDTO;
import com.agb.proyectsecurityjwt.dto.AuthenticationResponseDTO;
import com.agb.proyectsecurityjwt.dto.RegisterRequestDTO;
import com.agb.proyectsecurityjwt.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDTO> register(@Valid @RequestBody RegisterRequestDTO request)  {

        try {
            return ResponseEntity.ok(service.register(request));

        } catch (Exception e) {

            throw new RuntimeException("Error authorization user", e);
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@Valid @RequestBody AuthenticationRequestDTO request) {

        try {
            return ResponseEntity.ok(service.authenticate(request));

        } catch (Exception e) {
            throw new RuntimeException("Error authentication user",e);
        }
    }
}