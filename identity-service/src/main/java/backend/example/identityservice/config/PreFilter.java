package backend.example.identityservice.config;

import backend.example.identityservice.exception.AppException;
import backend.example.identityservice.exception.ErrorCode;
import backend.example.identityservice.repository.UserRepository;
import backend.example.identityservice.service.JwtService;

import backend.example.identityservice.utils.TokenType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;



@Component
@Slf4j
@RequiredArgsConstructor
public class PreFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("---------- doFilterInternal ----------");

        final String authorization = request.getHeader(AUTHORIZATION);
        log.info("Authorization: {}", authorization);

        if (StringUtils.isBlank(authorization) || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authorization.substring("Bearer ".length());
        log.info("Token: {}", token);

        final String email = jwtService.extractUsername(token, TokenType.ACCESS_TOKEN);

        if (StringUtils.isNotEmpty(email) && SecurityContextHolder.getContext().getAuthentication() == null) {
            log.info("User1: {}", email);

            UserDetails userDetails = userRepository.findByEmail(email)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
            log.info("User2: {}", userDetails.getUsername());
            if (jwtService.isValid(token, TokenType.ACCESS_TOKEN, userDetails)) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                log.info("Authentication: {}", authentication);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
                log.info("Successfully authenticated user: {}", userDetails.getUsername());
            }
        }

        filterChain.doFilter(request, response);
    }
}