package com.agb.proyectsecurityjwt.configuration;

import com.agb.proyectsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * This class is responsible for configuring and providing essential components related to
 * user authentication and security within the Spring application. It defines a UserDetailsService
 * to load user details from a repository, a PasswordEncoder for securely handling passwords,
 * and an AuthenticationProvider for the authentication process. Additionally, it provides access
 * to the AuthenticationManager to manage authentication providers.
 */

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    // Load user details from the repository based on the username (in this case, the email).
    @Bean
    public UserDetailsService userDetailsService() {

        return username -> userRepository.findByEmail(username)
                .orElseThrow( () -> new UsernameNotFoundException("User not found"));
    }

    // Password encoder for securely encrypting and verifying user passwords.
    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }


    // Authentication process
    @Bean
    public AuthenticationProvider authenticationProvider() {

        // Create and configure a DaoAuthenticationProvider object.
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Configure the user details service for the authentication provider.
        authProvider.setUserDetailsService(userDetailsService());

        // Assign the password encoder to the authentication provider.
        authProvider.setPasswordEncoder(passwordEncoder());

        // Return the configured authentication provider.
        return authProvider;
    }


    // Provides access to the AuthenticationManager for managing providers.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}