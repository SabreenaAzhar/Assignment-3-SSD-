package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.RateLimiterService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/*
 * * 2. Access Control:
 *    - All /api/accounts endpoints now require authentication.
 *    - Only the logged-in user can access or modify their own account data.
 *
 * 3. Resource Ownership Enforcement:
 *    - Ownership validation ensures that users cannot access or manipulate accounts they do not own.
 *    - Each request cross-checks authenticated username with account ownerId.
 *
 * 5. Rate Limiting:
 *    - Applied request rate limiting using RateLimiterService to prevent brute-force or abuse on transfers.
 *    - Limits transfers to 3 per minute per user.
 *
 * 8. Error Handling & Logging:
 *    - Returns clear, minimal, and secure error messages (no stack traces or sensitive details).
 *    - Uses HTTP status codes (403, 400, 429) for access, validation, and rate-limit violations.
 *
 * 9. Input Validation:
 *    - Rejects invalid, zero, or negative transfer amounts.
 *    - Checks for sufficient account balance before performing updates.
 */

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final RateLimiterService rateLimiter;

    public AccountController(AccountRepository accounts, AppUserRepository users, RateLimiterService rateLimiter) {
        this.accounts = accounts;
        this.users = users;
        this.rateLimiter = rateLimiter;
    }

     /**
     * (2) Access Control & (3) Ownership Enforcement
     * Only allow viewing the balance of your own account.
     * Returns 403 if user tries to access another user's account.
     */
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        // Ownership check// (3) Ownership check — ensure account belongs to authenticated user
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("accountId", a.getId());
        response.put("balance", a.getBalance());
        return ResponseEntity.ok(response);
    }

    /**
     * (5) Rate Limiting, (3) Ownership Enforcement, (9) Input Validation
     * Secure transfer endpoint:
     * - Enforces rate limit (3 per minute)
     * - Validates account ownership
     * - Checks input and balance
     */
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
        String userKey = "transfer:" + me.getUsername();

        // (5) Apply rate limiting (3 attempts/minute per user)
        if (!rateLimiter.tryConsume(userKey)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many requests — slow down"));
        }

        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        // (3) Ownership enforcement — prevent cross-account transfers
        if (!a.getOwnerUserId().equals(me.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied — not your account"));
        }

        // (9) Input Validation — reject invalid or negative amounts
        if (amount <= 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid transfer amount"));
        }

        if (a.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Insufficient funds"));
        }
        // Perform balance deduction safely
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remainingBalance", a.getBalance());
        return ResponseEntity.ok(response);
    }

    /**
     * (2) Access Control & (3) Ownership Enforcement
     * Safe endpoint: Lists only the authenticated user's accounts.
     */
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
