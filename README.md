# Spring Boot Security Framework Starter (`security-framework`)

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.6-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, opinionated Spring Boot starter library delivering stateless **JWT Authentication**, **Refresh Token Rotation (RTR)**, **JTI Token Revocation**, and expression-based **Role-Based Access Control (RBAC)** with zero boilerplate code required in consuming applications.

---

## Architecture Overview
 Features
Stateless JWT Authentication
Refresh Token Rotation (RTR)
JTI-Based Token Revocation
Role-Based Access Control (RBAC)
Role Hierarchy Support
Custom Permission Evaluation
Account Lock Detection
Auto Configuration
Security Exception Handling
SPI-Based Extensibility
OTP Infrastructure
Two-Factor Authentication Infrastructure
Audit Event Infrastructure
Verification Infrastructure
Production-Ready Spring Security Integration

Architecture Overview
[ HTTP Request ]
        │
        ▼
[ JwtAuthenticationFilter ]
        │
        ├── Validate JWT Signature
        ├── Check Token Expiry
        ├── Check JTI Revocation
        ├── Load User via UserLookupProvider
        ├── Validate Account Status
        └── Populate SecurityContext
                    │
                    ▼
        [ Spring Security ]
                    │
                    ▼
        [ Method Security ]
                    │
        ├── hasRole(...)
        ├── hasAuthority(...)
        └── hasPermission(...)
        
Installation
Maven
<dependency>
    <groupId>io.github.dollopinfotech</groupId>
    <artifactId>security-framework</artifactId>
    <version>1.0.0</version>
</dependency>

Configuration
application.yml
security:
  core:
    bcrypt-strength: 12
    public-urls:
      - /api/v1/auth/**
      - /actuator/health

  jwt:
    access-secret: "YOUR_ACCESS_SECRET"
    refresh-secret: "YOUR_REFRESH_SECRET"

  rbac:
    enabled: true
UserLookupProvider SPI

The consuming application must provide a user lookup implementation.

@Component
public class UserLookupProviderImpl implements UserLookupProvider {

    private final UserRepository userRepository;

    public UserLookupProviderImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<SecurityPrincipal> findByIdentifier(String identifier) {
        return userRepository.findByEmail(identifier)
                .map(UserAdapter::new);
    }
}
SecurityPrincipal Implementation
public class UserAdapter implements SecurityPrincipal {

    private final User user;

    public UserAdapter(User user) {
        this.user = user;
    }

    @Override
    public String getIdentifier() {
        return user.getEmail();
    }

    @Override
    public Set<String> getAuthorities() {
        return Set.of("ROLE_USER");
    }

    @Override
    public String getAuthProvider() {
        return "LOCAL";
    }

    @Override
    public boolean isAccountLocked() {
        return false;
    }

    @Override
    public boolean isMfaEnabled() {
        return false;
    }
}
RBAC Example
@RestController
public class UserController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String user() {
        return "User Resource";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "Admin Resource";
    }
}
Authentication Flow
User authenticates.
Framework generates JWT access token.
Client sends token in Authorization header.
JwtAuthenticationFilter validates token.
UserLookupProvider loads current user.
Authorities are loaded into SecurityContext.
RBAC rules are evaluated.
Request is processed.
Configuration Reference
Property	Default	Description
security.core.enabled	true	Enables framework
security.core.bcrypt-strength	12	BCrypt rounds
security.core.public-urls	[]	Public endpoints
security.jwt.access-secret	Required	Access token secret
security.jwt.refresh-secret	Required	Refresh token secret
security.jwt.access-token-expiration-minutes	15	Access token TTL
security.jwt.refresh-token-expiration-days	7	Refresh token TTL
security.rbac.enabled	true	Enables RBAC
Extension Points

The framework exposes SPI interfaces for customization:

UserLookupProvider
CurrentUserResolver
RoleHierarchyProvider
ResourcePermissionEvaluator
AuditEventListener
OtpSender
EmailService
SmsService
NotificationSender
Verified Features

The following features have been tested through a separate consumer application:

JWT Authentication
Public URL Configuration
Private Endpoint Protection
RBAC Authorization
Role Hierarchy
User Role Access
Admin Role Access
Security Exception Handling
Production Recommendations
Use Redis or JDBC-based token revocation storage.
Store secrets in environment variables or secret managers.
Enable HTTPS in production.
Rotate signing keys periodically.
Monitor authentication and authorization events.
License

Apache License 2.0
 
