package com.dollop.app.autoconfigure;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.dollop.app.jwt.JwtProvider;
import com.dollop.app.jwt.JwtValidator;
import com.dollop.app.jwt.RefreshTokenService;
import com.dollop.app.jwt.TokenRevocationStore;
import com.dollop.app.jwt.impl.DefaultJwtProvider;
import com.dollop.app.jwt.impl.DefaultJwtValidator;
import com.dollop.app.jwt.impl.DefaultRefreshTokenService;
import com.dollop.app.jwt.impl.InMemoryTokenRevocationStore;
import com.dollop.app.security.core.SecurityErrorResponseWriter;
import com.dollop.app.security.filter.JwtAuthenticationFilter;
import com.dollop.app.spi.user.UserLookupProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Auto-configuration for JWT authentication and refresh token subsystem.
 *
 * <p>Activated when {@code security.jwt.access-secret} configuration property is defined.
 * Configures {@link JwtValidator}, {@link JwtProvider}, {@link TokenRevocationStore},
 * {@link RefreshTokenService}, and {@link JwtAuthenticationFilter}.</p>
 *
 * <p>All bean registrations honor consumer SPI overrides via {@code @ConditionalOnMissingBean}.</p>
 *
 * @since Phase 7.5
 */
@AutoConfiguration(before = SecurityCoreAutoConfiguration.class)
@ConditionalOnClass(JwtValidator.class)
@EnableConfigurationProperties({JwtProperties.class, SecurityCoreProperties.class})
@ConditionalOnProperty(prefix = "security.jwt", name = "access-secret")
public class JwtAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtValidator.class)
    public JwtValidator jwtValidator(JwtProperties jwtProperties) {
        return new DefaultJwtValidator(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean(JwtProvider.class)
    public JwtProvider jwtProvider(JwtProperties jwtProperties) {
        return new DefaultJwtProvider(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean(TokenRevocationStore.class)
    public TokenRevocationStore tokenRevocationStore() {
        return new InMemoryTokenRevocationStore();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityErrorResponseWriter.class)
    public SecurityErrorResponseWriter securityErrorResponseWriter(
            ObjectProvider<ObjectMapper> objectMapperProvider) {
        ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
        return new SecurityErrorResponseWriter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(RefreshTokenService.class)
    public RefreshTokenService refreshTokenService(
            JwtValidator jwtValidator,
            JwtProvider jwtProvider,
            TokenRevocationStore tokenRevocationStore,
            ObjectProvider<UserLookupProvider> userLookupProvider) {
        return new DefaultRefreshTokenService(
                jwtValidator,
                jwtProvider,
                tokenRevocationStore,
                userLookupProvider.getIfAvailable()
        );
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationFilter.class)
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtValidator jwtValidator,
            ObjectProvider<UserLookupProvider> userLookupProvider,
            TokenRevocationStore tokenRevocationStore,
            SecurityErrorResponseWriter errorResponseWriter,
            SecurityCoreProperties coreProperties,
            JwtProperties jwtProperties) {
        return new JwtAuthenticationFilter(
                jwtValidator,
                userLookupProvider.getIfAvailable(),
                tokenRevocationStore,
                errorResponseWriter,
                coreProperties,
                jwtProperties
        );
    }
}
