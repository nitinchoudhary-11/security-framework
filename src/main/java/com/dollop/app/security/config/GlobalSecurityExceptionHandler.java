package com.dollop.app.security.config;

import com.dollop.app.security.core.exception.SecurityFrameworkException;
import com.dollop.app.security.core.model.SecurityErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalSecurityExceptionHandler {

    @ExceptionHandler(SecurityFrameworkException.class)
    public ResponseEntity<SecurityErrorResponse> handleSecurityFrameworkException(SecurityFrameworkException ex, HttpServletRequest request) {
        SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(ex.getStatus())
                .error(HttpStatus.valueOf(ex.getStatus()).getReasonPhrase())
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(ex.getStatus()).body(errorResponse);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<SecurityErrorResponse> handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request) {
        SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error(HttpStatus.FORBIDDEN.getReasonPhrase())
                .message("You do not have permission to access this resource")
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<SecurityErrorResponse> handleAuthenticationException(AuthenticationException ex, HttpServletRequest request) {
        SecurityErrorResponse errorResponse = SecurityErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error(HttpStatus.UNAUTHORIZED.getReasonPhrase())
                .message("Authentication failed")
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }
}
