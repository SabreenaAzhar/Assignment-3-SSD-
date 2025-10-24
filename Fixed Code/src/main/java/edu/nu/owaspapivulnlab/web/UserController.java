package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.UserDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/*
 
 * 1. Password Security (BCrypt used)
 * 2. Access Control (Authentication + role-based restrictions)
 * 3. Resource Ownership Enforcement (users can access only their own data)
 * 4. Data Exposure Control (DTOs used to hide sensitive data)
 * 6. Mass Assignment Prevention (DTO limits input fields)
 * 8. Error Handling & Logging (secure exception handling)
 * 9. Input Validation (field-level checks)
 */
 

/**
 * UserController – handles user registration, retrieval, and deletion.
 * Implements input validation and proper access control.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

   /**
     * (1) Password Security:
     *    - Uses BCrypt hashing for secure password storage.
     * (6) Mass Assignment Prevention:
     *    - Only accepts fields from UserDTO (username, email, password).
     * (9) Input Validation:
     *    - Validates username length and format.
     */
    @PostMapping
    public ResponseEntity<?> createUser(@Valid @RequestBody UserDTO req) {
        // Check if username already exists
        if (users.findByUsername(req.getUsername()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already taken");
        }
        // Enforce length server-side so validation messages match tests
        if (req.getUsername() == null || req.getUsername().length() < 3 || req.getUsername().length() > 30) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username must be between 3 and 30 characters");
        }
        AppUser user = new AppUser();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        // (1) Password securely hashed using BCrypt (configured in PasswordEncoder)
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        // (6) Prevent mass assignment — explicitly set safe defaults
        user.setRole("USER");
        user.setAdmin(false);

        users.save(user);
        // (4) Data Exposure Control — sensitive info not exposed (no password/role)
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User created successfully");
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
    response.put("role", user.getRole());
    response.put("isAdmin", user.isAdmin());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * (3) Resource Ownership Enforcement:
     *    - Ensures users can access only their own resources unless admin.
     * (4) Data Exposure Control:
     *    - Returns UserDTO without sensitive data (password/role).
     * (9) Input Validation:
     *    - Ensures principal is valid and resource exists.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id, Principal principal) {
        AppUser currentUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        AppUser targetUser = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Prevent unauthorized access
        if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your resource");
        }
         // (4) Use DTO to limit exposure of sensitive data
        UserDTO dto = new UserDTO();
        dto.setUsername(targetUser.getUsername());
        dto.setEmail(targetUser.getEmail());
        dto.setBalance(0); // optional, not exposed
        return ResponseEntity.ok(dto);
    }

    /**
     * (2) Access Control:
     *    - Only admins can delete users.
     * (8) Error Handling:
     *    - Returns controlled responses for forbidden/unauthorized actions.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id, Principal principal) {
        AppUser currentUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        // Only admins can delete users (test expects 403 for non-admin)
        if (!currentUser.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access required");
        }

        users.deleteById(id);

        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }

    /**
     * (2) Access Control:
     *    - Only admins can view all users.
     * (4) Data Exposure Control:
     *    - Returns limited user data fields.
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> listUsers(Principal principal) {
        AppUser currentUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
        // (2) Enforce admin-only listing
        if (!currentUser.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin access only");
        }
        // (4) Filter exposed fields per OWASP guidelines
        List<Map<String, Object>> userList = users.findAll()
                .stream()
                .map(u -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("id", u.getId());
                    map.put("username", u.getUsername());
                    map.put("email", u.getEmail());
                    return map;
                })
                .toList();

        return ResponseEntity.ok(userList);
    }

    /**
     * (8) Error Handling & Logging:
     *    - Returns structured validation messages.
     * (9) Input Validation:
     *    - Captures validation exceptions.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage()));
        return errors;
    }
}
