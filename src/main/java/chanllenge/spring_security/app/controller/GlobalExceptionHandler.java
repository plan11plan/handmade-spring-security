package chanllenge.spring_security.app.controller;

import chanllenge.spring_security.authentication.exception.AuthenticationCredentialsNotFoundException;
import chanllenge.spring_security.authorization.exception.AccessDeniedException;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationCredentialsNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleAuthenticationCredentialsNotFoundException(
            AuthenticationCredentialsNotFoundException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Unauthorized");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAuthorizationDeniedException(
            AuthorizationDeniedException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Forbidden");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(
            AccessDeniedException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("error", "Forbidden");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }
}
