# Spring Boot Security Framework Starter (`security-framework`)

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.6-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, opinionated Spring Boot starter library delivering stateless **JWT Authentication**, **Refresh Token Rotation (RTR)**, **JTI Token Revocation**, and expression-based **Role-Based Access Control (RBAC)** with zero boilerplate code required in consuming applications.

---

## Architecture Overview

```
[ HTTP Request ] ──► [ JwtAuthenticationFilter ]
                            │
                            ├─► Validates ACCESS Key Signature (JJWT 0.12.7)
                            ├─► Checks JTI Revocation (TokenRevocationStore)
                            ├─► Loads Live User & Authorities (UserLookupProvider SPI)
                            ├─► Enforces Account-Lock State
                            └─► Populates SecurityContextHolder
                                      │
                                      ▼
                      [ Method Security / SpEL ]
                            │
                            ├─► @PreAuthorize("hasRole('ADMIN')") ──► RoleHierarchyProvider
                            └─► @PreAuthorize("hasPermission(#doc, 'write')") ──► ResourcePermissionEvaluator
```

---

## Quick Start

### 1. Add Maven Dependency

```xml
<dependency>
    <groupId>io.github.dollopinfotech</groupId>
    <artifactId>security-framework</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 2. Configure `application.yml`

```yaml
security:
  core:
    bcrypt-strength: 12
    public-urls:
      - /api/v1/auth/**
      - /actuator/health
  jwt:
    access-secret: "v9y$B&E)H@MbQeThWmZq4t7w!z%C*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeShVkYp"
    refresh-secret: "gVkYp3s6v9y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8x/A?D(G+Kb"
  rbac:
    enabled: true
```

### 3. Implement `UserLookupProvider` SPI

```java
@Component
public class UserLookupProviderImpl implements UserLookupProvider {

    private final UserRepository userRepository;

    public UserLookupProviderImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<SecurityPrincipal> findByIdentifier(String identifier) {
        return userRepository.findByEmail(identifier).map(UserAdapter::new);
    }
}
```

---

## Configuration Reference

| Property Name | Default Value | Required? | Description |
|:---|:---:|:---:|:---|
| `security.core.enabled` | `true` | Optional | Toggles security framework auto-configuration. |
| `security.core.bcrypt-strength` | `12` | Optional | Rounds for BCrypt password hashing. |
| `security.core.public-urls` | `[]` | Optional | Endpoints that bypass authentication. |
| `security.core.allowed-origins` | `[]` | Optional | Allowed CORS origins (no wildcard default). |
| `security.jwt.access-secret` | *None* | **Required for JWT** | Secret key for access token signing (min 256-bit). |
| `security.jwt.refresh-secret` | *None* | **Required for JWT** | Secret key for refresh token signing (min 256-bit). |
| `security.jwt.access-token-expiration-minutes` | `15` | Optional | Access token TTL in minutes. |
| `security.jwt.refresh-token-expiration-days` | `7` | Optional | Refresh token TTL in days. |
| `security.jwt.cookie-name` | *None* | Optional | HttpOnly cookie name for access tokens. |
| `security.rbac.enabled` | `true` | Optional | Activates method security and role hierarchy. |

---

## Production Deployment Recommendations

- **Clustered Multi-Node Deployments:** Replace default `InMemoryTokenRevocationStore` with a distributed Redis or JDBC `TokenRevocationStore` `@Bean`.
- **Secret Isolation:** Store `access-secret` and `refresh-secret` in environment variables or key vaults (AWS Secrets Manager / Vault). Never commit secrets to repository.

---

## License

Distributed under the Apache 2.0 License.
