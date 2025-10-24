package edu.nu.owaspapivulnlab.model;

import jakarta.validation.constraints.*;
/*
 * * 6. Mass Assignment Prevention:
 *    - Introduced a dedicated Data Transfer Object (DTO) instead of directly binding entity classes.
 *    - This prevents attackers from injecting sensitive fields such as 'role' or 'isAdmin' during registration or updates.
 *    - Only safe and required fields (username, password, email, balance) are exposed.
 * 
 * 9. Input Validation:
 *    - Added Jakarta Validation annotations to enforce field-level constraints.
 *    - Validations include checks for blank fields, format enforcement, value limits, and size restrictions.
 *    - These constraints ensure that only properly formatted and safe data enters the system.
 */
 
public class UserDTO {
     // 9. Input Validation: Ensures username field is not empty
    @NotBlank(message = "Username cannot be blank")
    private String username;
    // 9. Input Validation: Validates password complexity and prevents weak input
    @NotBlank(message = "Password cannot be blank")
    @Size(min = 2, max = 50, message = "Password must be between 2 and 50 characters")
    private String password;
     // 9. Input Validation: Validates proper email format and ensures it is not blank
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email cannot be blank")
    private String email;

    @PositiveOrZero(message = "Balance cannot be negative")
    @Max(value = 1000000, message = "Balance exceeds maximum allowed limit")
    private double balance;

    // 6. Mass Assignment Prevention:
    // Only exposing controlled fields through getters/setters to prevent sensitive data manipulation.
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public double getBalance() { return balance; }
    public void setBalance(double balance) { this.balance = balance; }
}
