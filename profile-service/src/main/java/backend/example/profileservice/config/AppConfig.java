package backend.example.profileservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@Slf4j
@EnableWebSecurity
@EnableMethodSecurity
public class AppConfig implements WebMvcConfigurer {
    private static final String[] PUBLIC_ENDPOINTS = {
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/actuator/**"
    };
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        log.info("==== Initializing SecurityFilterChain for Profile Service ====");

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorRequests -> authorRequests
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(manager -> manager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );
        
        return httpSecurity.build();
    }
}