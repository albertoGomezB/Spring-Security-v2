package com.agb.proyectsecurityjwt.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This is a temporary DTO (Data Transfer Object) used to receive registration data
 * before creating and saving a User instance in the database.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequestDTO {

    @NotBlank(message = "First name cannot be empty")
    private String firstname;

    @NotBlank(message = "Last name cannot be empty")
    private String lastname;

    @Email(message = "Email should be valid")
    private String email;

    @Size(min = 6, message = "Password must have at least 6 characters")
    private String password;
}


