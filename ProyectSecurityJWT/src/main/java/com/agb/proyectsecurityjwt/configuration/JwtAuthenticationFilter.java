package com.agb.proyectsecurityjwt.configuration;

import com.agb.proyectsecurityjwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** When an HTTP request is received, this filter checks to see if it contains a JWT token in the authorization header.
 If a valid token is found and the user is not yet authenticated (not logged in),
 the filter authenticates you and allows you to access resources protected by the application.

 Think of it as a kind of "key" that the user presents with each request.
 If the key is valid and the user is not already inside the house (not logged in),
 you are allowed to enter; otherwise, you are prompted to log in first. */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                   @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Gets the "Authorization" header of the request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;


        // If the authorized header is null or does not start with "Bearer", continue with the filter chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7); // Extracts the JWT token from the header string, excluding "Bearer ".
        userEmail = jwtService.extractUserName(jwt); // Extracts the username from the JWT token.


        // If a username was extracted from the token and there is no current authentication in the security context:
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load the user details corresponding to the username extracted from the token.
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            // If the JWT token is valid for the user:
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // Creates an object to authenticate the user and associates it with their details and authorities.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, // The details of the user
                        null, // The password (not used in this case, since it is a JWT authentication)
                        userDetails.getAuthorities() // The user's authorities or roles
                );

                // Sets the authentication details, such as the IP address and other information for the request.
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                // Stores the authentication information in the Spring security context.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

            // Continue with the filter chain.
            filterChain.doFilter(request, response);

        }
    }
}
