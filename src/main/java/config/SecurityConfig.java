package com.letocart.java_apirest_2026.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
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

    /**
     * Configuration des utilisateurs en mémoire (pour le développement)
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        // Utilisateur avec rôle USER
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("userpassword"))
                .roles("USER")
                .build();

        // Utilisateur avec rôle ADMIN
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("adminpassword"))
                .roles("ADMIN", "USER")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    /**
     * Configuration de l'encodeur de mot de passe (BCrypt)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configuration de la chaîne de filtres de sécurité
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Configuration de l'autorisation des requêtes
                .authorizeHttpRequests(auth -> auth
                        // Swagger UI accessible sans authentification
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll()
                        // Endpoints admin réservés au rôle ADMIN
                        .requestMatchers("/api/accounts/**").hasRole("ADMIN")
                        // Tous les autres endpoints nécessitent une authentification
                        .anyRequest().authenticated()
                )
                // Activation de l'authentification HTTP Basic
                .httpBasic(Customizer.withDefaults())
                // Désactivation de CSRF (pour les API REST)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
