package com.dollop.app.sample.provider;

import com.dollop.app.auth.ResourcePermissionEvaluator;
import com.dollop.app.user.SecurityPrincipal;
import org.springframework.stereotype.Component;

/**
 * Sample implementation of ResourcePermissionEvaluator SPI supporting domain object access control.
 */
@Component
public class SampleResourcePermissionEvaluator implements ResourcePermissionEvaluator {

    @Override
    public boolean hasPermission(SecurityPrincipal principal, Object targetDomainObject, String permission) {
        if (principal == null || permission == null) {
            return false;
        }

        // ADMIN role bypasses permission checks
        if (principal.getAuthorities().contains("ROLE_ADMIN")) {
            return true;
        }

        // Domain object permission checks
        if ("document".equals(targetDomainObject)) {
            if ("read".equals(permission)) {
                return principal.getAuthorities().contains("DOC_READ");
            }
            if ("write".equals(permission)) {
                return principal.getAuthorities().contains("DOC_WRITE");
            }
        }

        return false;
    }
}
