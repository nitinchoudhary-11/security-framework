package com.dollop.app.autoconfigure;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.dollop.app.security.config.handler.CustomAccessDeniedHandler;
import com.dollop.app.security.config.handler.CustomAuthenticationEntryPoint;
import com.dollop.app.security.core.userdetails.SecurityPrincipalUserDetails;
import com.dollop.app.security.filter.JwtAuthenticationFilter;
import com.dollop.app.spi.user.CurrentUserResolver;
import com.dollop.app.user.SecurityPrincipal;

/**
 * Core AutoConfiguration for the Spring Security Framework.
 *
 * <p>Registers essential security infrastructure beans including {@link PasswordEncoder},
 * {@link AuthenticationManager}, {@link CorsConfigurationSource}, {@link GrantedAuthorityDefaults},
 * and the primary {@link SecurityFilterChain}.</p>
 *
 * <p>Honors consumer-defined bean overrides via {@code @ConditionalOnMissingBean}.</p>
 *
 * @since Phase 7.5
 */
@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(SecurityCoreProperties.class)
@ConditionalOnProperty(prefix = "security.core", name = "enabled", matchIfMissing = true)
public class SecurityCoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(CurrentUserResolver.class)
    public CurrentUserResolver currentUserResolver() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                Object principal = authentication.getPrincipal();
                if (principal instanceof SecurityPrincipal securityPrincipal) {
                    return Optional.of(securityPrincipal);
                }
                if (principal instanceof SecurityPrincipalUserDetails userDetails) {
                    return Optional.of(userDetails.getPrincipal());
                }
            }
            return Optional.empty();
        };
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder(SecurityCoreProperties properties) {
        return new BCryptPasswordEncoder(properties.getBcryptStrength());
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean(CorsConfigurationSource.class)
    public CorsConfigurationSource corsConfigurationSource(SecurityCoreProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> allowedOrigins = properties.getAllowedOrigins();
        if (allowedOrigins != null && !allowedOrigins.isEmpty()) {
            configuration.setAllowedOrigins(allowedOrigins);
        }
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @ConditionalOnMissingBean(GrantedAuthorityDefaults.class)
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("ROLE_");
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SecurityCoreProperties properties,
            CorsConfigurationSource corsConfigurationSource,
            ObjectProvider<JwtAuthenticationFilter> jwtAuthenticationFilterProvider,
            ObjectProvider<CustomAuthenticationEntryPoint> authenticationEntryPointProvider,
            ObjectProvider<CustomAccessDeniedHandler> accessDeniedHandlerProvider) throws Exception {

        List<String> publicUrlsList = properties.getPublicUrls();
        String[] publicUrls = (publicUrlsList != null && !publicUrlsList.isEmpty())
                ? publicUrlsList.toArray(new String[0])
                : new String[0];

        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exceptions -> {
                authenticationEntryPointProvider.ifAvailable(exceptions::authenticationEntryPoint);
                accessDeniedHandlerProvider.ifAvailable(exceptions::accessDeniedHandler);
            })
            .authorizeHttpRequests(auth -> {
                if (publicUrls.length > 0) {
                    auth.requestMatchers(publicUrls).permitAll();
                }
                auth.requestMatchers("/error").permitAll();
                auth.anyRequest().authenticated();
            });

        JwtAuthenticationFilter jwtFilter = jwtAuthenticationFilterProvider.getIfAvailable();
        if (jwtFilter != null) {
            http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }
}
