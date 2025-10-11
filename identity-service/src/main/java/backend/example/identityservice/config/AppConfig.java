package backend.example.identityservice.config;


import backend.example.identityservice.service.impl.UserService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


@Configuration
@RequiredArgsConstructor
@Slf4j
@EnableWebSecurity
@EnableMethodSecurity
public class AppConfig implements WebMvcConfigurer {
    private final UserService userService;
    private final PreFilter preFilter;

    private static final String[] PUBLIC_ENDPOINTS = {
            "/users/registration", "/auth/token", "/auth/introspect", "/auth/logout", "/auth/refresh"
    };

    @Bean
    PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 3. UserDetailsService
    @Bean
    public UserDetailsService userDetailsService() {
        return userService::findByEmail; // hoặc findByUsername nếu bạn dùng username

    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        log.info("==== Initializing SecurityFilterChain ====");

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorRequests -> authorRequests
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(manager -> manager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(preFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }



    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring()
                .requestMatchers("/actuator/**", "/v3/**", "/webjars/**", "/swagger-ui*/*swagger-initializer.js", "/swagger-ui*/**");
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }


}