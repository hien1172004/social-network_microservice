package backend.example.profileservice.config;

import backend.example.profileservice.dto.response.UserProfileResponse;
import backend.example.profileservice.entity.UserProfile;
import backend.example.profileservice.exception.AppException;
import backend.example.profileservice.exception.ErrorCode;
import backend.example.profileservice.repository.UserProfileRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PreFilter extends OncePerRequestFilter {
    UserProfileRepository userProfileRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Extract user info from headers (set by Gateway)
        String userId = request.getHeader("X-User-Id");
        String rolesHeader = request.getHeader("X-User-Roles");

        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                List<GrantedAuthority> authorities = createAuthoritiesFromHeader(rolesHeader);
                // Create authentication with authorities
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Successfully authenticated user from headers: {} with roles: {}", authentication.getName(), rolesHeader);
            } catch (Exception e) {
                log.error("Failed to authenticate user from headers: {}", e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    private List<GrantedAuthority> createAuthoritiesFromHeader(String rolesHeader) {
        if (rolesHeader == null || rolesHeader.isEmpty()) {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return Arrays.stream(rolesHeader.split(","))
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .map(role -> {
                    String roleName = role.toUpperCase();
                    if (!roleName.startsWith("ROLE_")) {
                        roleName = "ROLE_" + roleName;
                    }
                    return new SimpleGrantedAuthority(roleName);
                })
                .collect(Collectors.toList());
    }
}
