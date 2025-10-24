package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/* 8. Error Handling & Logging:
 *    - Introduced a global exception handler using @ControllerAdvice.
 *    - Prevents exposure of internal server or database details to clients.
 *    - Provides consistent, OWASP-compliant JSON error responses.
 *    - Logs detailed error messages (stack traces) on the server side only.
 *    - Returns appropriate HTTP status codes (400, 403, 404, 429, 500).
 *    - Separately handles validation, database, runtime, and JSON parsing errors.
 */


/**
 * (8) Global Exception Handler
 * ----------------------------
 * Hides sensitive technical details
 * Logs errors securely
 * Returns structured, consistent API responses
 */
@ControllerAdvice
public class GlobalErrorHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalErrorHandler.class);

    /**
     * (8.1) Handle malformed JSON (400 Bad Request)
     * Prevents detailed parsing errors from leaking to the client.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> handleBadJson(HttpMessageNotReadableException ex, WebRequest request) {
        logger.warn("Bad request (invalid JSON): {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Bad Request");
        response.put("message", "Invalid or malformed JSON in request body.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

   /**
     * (8.2) Handle validation errors
     * Prevents exposure of validation internals to the client.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidationErrors(MethodArgumentNotValidException ex, WebRequest request) {
        logger.warn("Validation error: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Validation Failed");
        response.put("message", "Invalid request data. Please verify input fields.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * (8.3) Handle database-related exceptions securely.
     * No SQL or DB error details are returned to the client.
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> handleDatabaseError(DataAccessException ex, WebRequest request) {
        logger.error("Database error: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("error", "Database Error");
        response.put("message", "A database operation failed. Please try again later.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * (8.4) Handle runtime exceptions.
     * Ensures no stack trace or sensitive internal messages leak to users.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> handleRuntimeExceptions(RuntimeException ex, WebRequest request) {
        logger.error("Runtime exception: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Runtime Error");
        response.put("message", "A processing error occurred.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * (8.5) Handle ResponseStatusExceptions.
     * Retains original status and sanitized reason.
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<?> handleResponseStatusException(ResponseStatusException ex, WebRequest request) {
        logger.warn("ResponseStatusException: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", ex.getStatusCode().value());
    response.put("error", ex.getStatusCode().toString());
        response.put("message", ex.getReason() == null ? ex.getMessage() : ex.getReason());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, ex.getStatusCode());
    }

    /**
     * (8.6) Catch-all handler for unexpected exceptions (500 Internal Server Error)
     * Protects system details and returns generic safe message.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleAllExceptions(Exception ex, WebRequest request) {
        logger.error("Unexpected server error: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("error", "Internal Server Error");
        response.put("message", "Something went wrong. Please contact support.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * (8.7) Handle 404 - Resource Not Found
     * Prevents leaking internal route or framework information.
     */
    @ExceptionHandler(org.springframework.web.servlet.NoHandlerFoundException.class)
    public ResponseEntity<?> handleNotFoundHandler(org.springframework.web.servlet.NoHandlerFoundException ex, WebRequest request) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.NOT_FOUND.value());
        response.put("error", "Not Found");
        response.put("message", "Resource not found");
        response.put("path", request.getDescription(false).replace("uri=", ""));
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    /**
     * (8.8) Handle missing static resources gracefully.
     */
    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<?> handleNoResourceFound(org.springframework.web.servlet.resource.NoResourceFoundException ex, WebRequest request) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", new Date());
        response.put("status", HttpStatus.NOT_FOUND.value());
        response.put("error", "Not Found");
        response.put("message", "Resource not found");
        response.put("path", request.getDescription(false).replace("uri=", ""));
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }
}
