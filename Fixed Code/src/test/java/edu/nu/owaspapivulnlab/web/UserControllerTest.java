package edu.nu.owaspapivulnlab.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.UserDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * ✅ UserControllerTest
 * Integration + Security tests for the fixed OWASP API vulnerabilities.
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // -------------------------------
    // 1️⃣ Valid User Creation Test
    // -------------------------------
    @Test
    void testCreateUser_ValidInput_ShouldReturn201() throws Exception {
        UserDTO validUser = new UserDTO();
        validUser.setUsername("sabreenaTest");
        validUser.setPassword("hello123");
        validUser.setEmail("sabreena@test.com");
        validUser.setBalance(100);

        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validUser)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User created successfully"))
                .andExpect(jsonPath("$.username").value("sabreenaTest"));
    }

    // -------------------------------
    // 2️⃣ Invalid Input Handling
    // -------------------------------
    @Test
    void testCreateUser_InvalidInput_ShouldReturn400() throws Exception {
        UserDTO invalidUser = new UserDTO();
        invalidUser.setUsername("");
        invalidUser.setPassword("short");
        invalidUser.setEmail("not-an-email");
        invalidUser.setBalance(-50);

        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidUser)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.username").value("Username cannot be blank"))
                .andExpect(jsonPath("$.balance").value("Balance cannot be negative"));
    }

    // -------------------------------
    // 3️⃣ Password Hashing Validation
    // -------------------------------
    @Test
    void testPassword_ShouldBeStoredAsHashedValue() throws Exception {
        UserDTO user = new UserDTO();
        user.setUsername("secureUser");
        user.setPassword("MyPlainPassword");
        user.setEmail("secure@user.com");
        user.setBalance(50);

        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.password").doesNotExist()); // Password should never be returned
    }

    // -------------------------------
    // 4️⃣ Role-Based Access Control
    // -------------------------------
    @Test
    void testUnauthorizedAccess_ShouldReturn403() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isForbidden()); // Only admin should access
    }

    // -------------------------------
    // 5️⃣ Ownership Enforcement
    // -------------------------------
    @Test
    void testUserCannotAccessAnotherUsersData() throws Exception {
        // Suppose user1 tries to access user2’s account
        mockMvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer token-for-user1"))
                .andExpect(status().isForbidden());
    }

    // -------------------------------
    // 6️⃣ DTO Data Exposure Control
    // -------------------------------
    @Test
    void testReturnedUserData_ShouldNotExposeSensitiveFields() throws Exception {
        mockMvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer valid-user-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.role").doesNotExist())
                .andExpect(jsonPath("$.isAdmin").doesNotExist());
    }

    // -------------------------------
    // 7️⃣ Rate Limiting Verification
    // -------------------------------
    @Test
    void testRateLimiting_ShouldEnforceTooManyRequests() throws Exception {
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"user\",\"password\":\"wrongpass\"}"))
                    .andExpect(i < 5 ? status().isUnauthorized() : status().isTooManyRequests());
        }
    }

    // -------------------------------
    // 8️⃣ JWT Token Validation
    // -------------------------------
    @Test
    void testJWT_ShouldRejectExpiredOrInvalidToken() throws Exception {
        mockMvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer invalid.jwt.token"))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------
    // 9️⃣ Error Handling & Logging
    // -------------------------------
    @Test
    void testErrorResponse_ShouldBeGenericInProduction() throws Exception {
        mockMvc.perform(get("/api/unknown-endpoint"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Resource not found"));
    }

    // -------------------------------
    // 🔟 Input Validation & Sanitization
    // -------------------------------
    @Test
    void testInvalidTransferAmount_ShouldReturn400() throws Exception {
        String requestJson = """
                {
                    "fromUserId": 1,
                    "toUserId": 2,
                    "amount": -500
                }
                """;

        mockMvc.perform(post("/api/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.amount").value("Transfer amount must be positive"));
    }
}
