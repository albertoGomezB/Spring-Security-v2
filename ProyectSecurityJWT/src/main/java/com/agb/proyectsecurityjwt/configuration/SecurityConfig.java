package com.agb.proyectsecurityjwt.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * This configuration class is responsible for configuring and managing application security.
 * It defines how routes and resources should be protected and establishes security-related policies.
 */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter; // Add filter to handle token-based authentication
    private final AuthenticationProvider authProvider; // Add the provider to authenticate users in a personalized way

    @Bean
    // is a global security configuration that defines how a series of filters should be applied
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll() // Allows all requests under "/auth/**" without authentication.
                        .anyRequest().authenticated() // Require authentication for all other requests.
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Set session management to STATELESS (sessionless).
                .authenticationProvider(authProvider) // Configures the custom AuthenticationProvider for authentication.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // Add the JWT filter (before this filter)

        return http.build(); // Returns the configured security filter chain.

    }

}
