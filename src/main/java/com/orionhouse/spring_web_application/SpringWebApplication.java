package com.orionhouse.spring_web_application.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${ACTUATOR_USER}")
    private String actuatorUser;

    @Value("${ACTUATOR_PASSWORD}")
    private String actuatorPassword;

    @Value("${ACTUATOR_ROLE}")
    private String actuatorRole;

    /**
     * Configure the security filter chain.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/actuator/health", "/actuator/info").permitAll()  // Public endpoints
                    .requestMatchers("/actuator/**").hasAuthority("ROLE_" + actuatorRole)  // Ensure role prefix
                    .anyRequest().authenticated()
            )
            .httpBasic();  // Enable basic authentication

        return http.build();
    }

    /**
     * Creates an in-memory user with password encoding.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username(actuatorUser)
                .password(passwordEncoder.encode(actuatorPassword))  // Encode password
                .authorities("ROLE_" + actuatorRole)  // Explicit role prefix
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    /**
     * Provides a password encoder bean.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Secure password encoding
    }
}
