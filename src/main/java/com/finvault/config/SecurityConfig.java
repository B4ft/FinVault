package com.finvault.config;

import com.finvault.filter.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * INTENTIONALLY WEAK Security Configuration for educational purposes.
 *
 * Vulnerabilities:
 * - CSRF disabled
 * - Frame options disabled (clickjacking possible, needed for H2 console)
 * - All /internal/** endpoints permitted (accessible from anywhere via SSRF)
 * - Admin protection is only in the controller (bypassable via JWT forgery)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // VULNERABILITY: CSRF disabled entirely
            .csrf(AbstractHttpConfigurer::disable)

            // VULNERABILITY: Frame options disabled (H2 console works, also clickjacking)
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
            )

            // Authorization rules - intentionally permissive
            .authorizeHttpRequests(auth -> auth
                // Public auth pages
                .requestMatchers("/auth/**").permitAll()
                // Static resources
                .requestMatchers("/static/**", "/css/**", "/js/**", "/webjars/**").permitAll()
                // H2 console
                .requestMatchers("/h2-console/**").permitAll()
                // VULNERABILITY: Internal endpoint accessible without authentication
                // (relies on network controls only - bypassed via SSRF)
                .requestMatchers("/internal/**").permitAll()
                // All other requests go through our JWT filter
                .anyRequest().permitAll()
            )

            // Disable Spring Security's default form login (we use our own)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)

            // Add our vulnerable JWT filter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
