package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/*
 * * 3. Authentication & Session Management:
 *    - Implements JWT-based authentication using secure token validation.
 *    - Ensures each request is verified only once per request lifecycle (using OncePerRequestFilter).
 *    - Extracts and validates tokens from the "Authorization" header with "Bearer " prefix.
 *    - Sets user authentication in the Spring Security context after successful token verification.
 *
 * 8. Error Handling & Logging:
 *    - Gracefully handles invalid, expired, or malformed JWTs using try-catch (JwtException).
 *    - Prevents application crashes and ensures invalid tokens are ignored securely.
 *    - Avoids leaking internal token details or stack traces to the client.
 */
 
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
     // 3. Authentication: Dependency Injection of JWT and UserDetails services
    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }
    /**
     * 3. Authentication & 8. Error Handling:
     * Intercepts every HTTP request once and verifies the JWT token.
     * If the token is valid, authenticates the user; otherwise, passes the request down the chain.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        // Extract the "Authorization" header
        final String authHeader = request.getHeader("Authorization");
        // 3. Authentication: Check for valid Bearer token format
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // If no valid header, continue the filter chain without setting authentication
            filterChain.doFilter(request, response);
            return;
        }
        // Remove the "Bearer " prefix to extract the token
        String token = authHeader.substring(7);
        String username;

        try {
            // 3. Authentication: Parse and validate the JWT token using JwtService
            Jws<Claims> claimsJws = jwtService.parse(token);
            username = claimsJws.getBody().getSubject();
        } catch (JwtException e) {
            // 8. Error Handling: Catch invalid/expired token and skip authentication
            filterChain.doFilter(request, response);
            return;
        }
        // If username is valid and no authentication is yet set, establish a new authenticated session
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            // Create an authenticated token with authorities
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
            // Attach request details to the authentication object
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
             // 3. Authentication: Set the authenticated user in the security context
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
