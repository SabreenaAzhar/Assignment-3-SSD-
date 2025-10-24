package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.service.RateLimiterService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder;
    private final RateLimiterService rateLimiterService; // ADD THIS FIELD

    // Inject RateLimiterService properly
    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder, RateLimiterService rateLimiterService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
        this.rateLimiterService = rateLimiterService; // Initialize here
    }

    // DTO for Login
    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}
        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    // DTO for Token Response
    public static class TokenRes {
        private String token;

        public TokenRes() {}
        public TokenRes(String token) { this.token = token; }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // LOGIN ENDPOINT with Rate Limiting
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        String username = req.username();

        // Step 1: Apply rate limiting before authentication
        if (!rateLimiterService.tryConsume(username)) {
            return ResponseEntity.status(429).body(Map.of(
                "error", "Too many login attempts. Try again in 1 minute."
            ));
        }

        // Step 2: Check credentials
        AppUser user = users.findByUsername(username).orElse(null);
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            // Issue a legacy weak token (no iss/aud) for login responses used by tests
            String token = jwt.issueWithoutIssuerAudience(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }

        // Step 3: Invalid credentials
        return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
    }

    // SIGNUP ENDPOINT
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AppUser req) {
        if (users.findByUsername(req.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
        }

        // Hash password before saving (Point 1)
        req.setPassword(passwordEncoder.encode(req.getPassword()));

        // Prevent mass assignment (Point 6)
        req.setRole("USER");
        req.setAdmin(false);

        users.save(req);
        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }
}
