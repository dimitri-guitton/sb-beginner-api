package com.example.sbbeginnerapi.configuration;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
    private String jwtKey = "c84fd2650c69856580b76b2d6a205b76783a8152d2f72391fa883f5febe8718d375ba9a43757233b441450bda4d03d685192ff52f70ea7cb212a92f808d77a1c11dea2597582072efed039d463ecc24043756ecd4734091f574ccfeef8b6897297a149e4ea57aa0f8187efc6c77650ab30a7d74aac9aecf50a4a075276b1ffdb633833b256ed0df8967281249fff50ae5c58d29fad84d8572710b8b7028533604557d2976835615a54a8175685850eafac875eade3772f678ac9c81789b5d519836a247c73ee48089342c8e4c75cc0cef209e69b8be15017fe3b22dca1805ffaca9382a4a53e619583a972bb738b1a975341a697e2676931540d45f59031f815";

    @Bean
    SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // On ne s’applique qu’à /api/token
                .securityMatcher("/api/token")
                // Désactivation de CSRF pour une API stateless
                .csrf(AbstractHttpConfigurer::disable)
                // Pas de session
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Toutes les requêtes sur ce matcher nécessitent d’être authentifiées
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                // Active l’authentification Basic
                .httpBasic(Customizer.withDefaults())
                // Désactive le form login
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // On s’applique à toutes les routes sous /api/ (sauf /api/token déjà traitée)
                .securityMatcher("/api/**")
                // Désactivation de CSRF pour une API stateless
                .csrf(AbstractHttpConfigurer::disable)
                // Gestion de session en mode stateless
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Toutes les requêtes nécessitent une authentification par JWT
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                // Configuration du resource server avec JWT
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // Désactive le form login
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // Pour toutes les autres routes
                .authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
                // Pas de session car ce n’est pas une API protégée
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Désactivation de CSRF
                .csrf(AbstractHttpConfigurer::disable)
                // Désactive le form login
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder().username("user").password(passwordEncoder().encode("user")).roles("USER").build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKeySpec secretKey = new SecretKeySpec(this.jwtKey.getBytes(), 0, this.jwtKey.getBytes().length, "RSA");
        return NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(this.jwtKey.getBytes()));
    }
}
