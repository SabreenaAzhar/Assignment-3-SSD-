package edu.nu.owaspapivulnlab.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/*
 * * 5. Rate Limiting:
 *    - Introduced Bucket4j-based rate limiting to prevent brute-force and abuse attacks.
 *    - Restricts excessive login attempts or repeated sensitive requests.
 *    - Configured to allow only 5 requests per minute per user/client.
 *    - Prevents denial-of-service (DoS) or password-guessing attempts.
 *
 * 8. Error Handling & Logging (Supporting Fix):
 *    - Returns clear boolean responses instead of exceptions for rate limit violations.
 *    - Integration with controllers ensures standardized HTTP 429 responses for blocked users.
 */
 

@Service
public class RateLimiterService {
    // Maintain a separate rate limit bucket for each unique user or IP
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    /**
     * 5. Rate Limiting:
     * Retrieve or create a rate-limiting bucket for the given user/client key.
     * Each bucket defines how many actions (e.g., login attempts) a user can perform within a time window.
     */
    // Return existing bucket for username or create new
    public Bucket resolveBucket(String key) {
        return buckets.computeIfAbsent(key, this::newBucket);
    }

     /**
     * 5. Rate Limiting:
     * Define the bucket configuration — allows 5 actions per minute per key.
     * If the limit is exceeded, further attempts are blocked until the next refill period.
     */
    private Bucket newBucket(String key) {
    // Allow up to 5 login attempts per minute (tests expect 5 then rate limit)
    Refill refill = Refill.intervally(5, Duration.ofMinutes(1));
    Bandwidth limit = Bandwidth.classic(5, refill);
        return Bucket.builder().addLimit(limit).build();
    }

     /**
     * 5. Rate Limiting:
     * Attempt to consume one token from the bucket.
     * Returns false if the rate limit has been reached — helps controller respond with HTTP 429.
     */
    public boolean tryConsume(String key) {
        Bucket bucket = resolveBucket(key);
        return bucket.tryConsume(1);
    }
}
