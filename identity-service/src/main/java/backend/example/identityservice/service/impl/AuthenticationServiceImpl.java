    package backend.example.identityservice.service.impl;

    import backend.example.event.dto.NotificationEvent;
    import backend.example.identityservice.dto.TokenPayload;
    import backend.example.identityservice.dto.request.*;
    import backend.example.identityservice.dto.response.IntrospectResponse;
    import backend.example.identityservice.dto.response.TokenResponse;
    import backend.example.identityservice.entity.RedisToken;
    import backend.example.identityservice.entity.Role;
    import backend.example.identityservice.entity.User;
    import backend.example.identityservice.exception.AppException;
    import backend.example.identityservice.exception.ErrorCode;
    import backend.example.identityservice.repository.RedisTokenRepository;
    import backend.example.identityservice.repository.RoleRepository;
    import backend.example.identityservice.repository.UserRepository;
    import backend.example.identityservice.repository.httpClient.ProfileClient;
    import backend.example.identityservice.service.AuthenticationService;
    import backend.example.identityservice.service.JwtService;
    import backend.example.identityservice.utils.AccountStatus;
    import backend.example.identityservice.utils.TokenType;
    import jakarta.servlet.http.HttpServletRequest;
    import lombok.RequiredArgsConstructor;
    import lombok.experimental.FieldDefaults;
    import lombok.extern.slf4j.Slf4j;
    import org.apache.commons.lang.StringUtils;
    import org.springframework.http.HttpHeaders;
    import org.springframework.kafka.core.KafkaTemplate;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.stereotype.Service;
    import java.util.Date;
    import java.util.Map;
    import java.util.Set;

    import static backend.example.identityservice.utils.TokenType.RESET_TOKEN;
    import static backend.example.identityservice.utils.TokenType.VERIFICATION_TOKEN;


    @Service
    @RequiredArgsConstructor
    @Slf4j
    @FieldDefaults(makeFinal = true, level = lombok.AccessLevel.PRIVATE)
    public class AuthenticationServiceImpl implements AuthenticationService {

        UserRepository userRepository;
        AuthenticationManager authenticationManager;
        JwtService jwtService;
        PasswordEncoder passwordEncoder;
        RoleRepository roleRepository;
        ProfileClient profileClient;
        RedisTokenRepository redisTokenRepository;
        KafkaTemplate<String, Object> kafkaTemplate;

        // ---------- Helper Methods ----------

        private String extractBearerToken(HttpServletRequest request) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isBlank(header) || !header.startsWith("Bearer ")) {
                throw new AppException(ErrorCode.INVALID_KEY);
            }
            return header.substring(7);
        }

        private TokenPayload parseAndCheckToken(String token, TokenType type) {
            TokenPayload payload = jwtService.parseToken(token, type);
            if (!redisTokenRepository.existsById(payload.getJwtId())) {
                throw new AppException(ErrorCode.TOKEN_REVOKED);
            }
            return payload;
        }

        private User getUserFromToken(String token, TokenType type) {
            String userId = jwtService.extractUserId(token, type);
            return userRepository.findById(userId)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        }

        private void saveTokenToRedis(TokenPayload payload, TokenType tokenType, String userId) {
            long ttl = (payload.getExpiredTime().getTime() - System.currentTimeMillis()) / 1000;
            redisTokenRepository.save(RedisToken.builder()
                    .jwtId(payload.getJwtId())
                    .userId(userId) // ✅ Lưu userId
                    .tokenType(tokenType) // ✅ Lưu tokenType
                    .expiration(ttl)
                    .build());
        }

        private Role getDefaultUserRole() {
            return roleRepository.findById("USER")
                    .orElseGet(() -> roleRepository.save(Role.builder()
                            .name("USER")
                            .description("Default role for normal users")
                            .build()));
        }

        private TokenResponse getTokenResponse(User user) {
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            TokenPayload payload = jwtService.parseToken(refreshToken, TokenType.REFRESH_TOKEN);
            saveTokenToRedis(payload, TokenType.REFRESH_TOKEN, user.getId());

            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(user.getId())
                    .build();
        }
        // -------------------- AUTH ENDPOINTS --------------------
        @Override
        public TokenResponse accessToken(SignInRequest request) {
            log.info("[LOGIN] user={}", request.getEmail());
            User user = userRepository.findByEmail(request.getEmail()).
                    orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
            if (!user.isEnabled()) {
                throw new AppException(ErrorCode.USER_NOT_ACTIVE);
            }

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
            log.info("[ACCESS_TOKEN] Login success for user: {}", request.getEmail());
            return getTokenResponse(user);
        }



        @Override
        public TokenResponse refreshToken(HttpServletRequest request) {
            log.info("[REFRESH_TOKEN] Requesting refresh token");

            String refreshToken = extractBearerToken(request);
            TokenPayload oldPayload = parseAndCheckToken(refreshToken, TokenType.REFRESH_TOKEN);
            User user = getUserFromToken(refreshToken, TokenType.REFRESH_TOKEN);

            redisTokenRepository.deleteById(oldPayload.getJwtId());

            return getTokenResponse(user);
        }

        @Override
        public String removeToken(HttpServletRequest request) {
            log.info("[REMOVE_TOKEN] Logout request");
            String token = extractBearerToken(request);

            String userId;
            TokenPayload payload = null;

            try {
                payload = jwtService.parseToken(token, TokenType.ACCESS_TOKEN);
                userId = payload.getUserId(); // ✅ Lấy từ payload luôn
            } catch (Exception e) {
                log.warn("[REMOVE_TOKEN] Token parse failed: {}", e.getMessage());
                // ✅ Extract từ expired token
                userId = jwtService.extractUserIdWithoutValidation(token, TokenType.ACCESS_TOKEN);
                log.info("[REMOVE_TOKEN] Extracted userId from expired token: {}", userId);
            }

            // Blacklist nếu token còn hạn
            if (payload != null && payload.getExpiredTime().after(new Date())) {
                saveTokenToRedis(payload, TokenType.ACCESS_TOKEN, userId);
                log.info("[REMOVE_TOKEN] Token blacklisted: {}", payload.getJwtId());
            } else {
                log.info("[REMOVE_TOKEN] Skip blacklist (token expired/invalid)");
            }

            // Xóa refresh token
            redisTokenRepository.deleteByUserIdAndTokenType(userId, TokenType.REFRESH_TOKEN);
            log.info("[REMOVE_TOKEN] Deleted refresh tokens for userId={}", userId);

            return "Logout successful";
        }

        @Override
        public String forgotPassword(String email) {
            log.info("[FORGOT_PASSWORD] email={}", email);
            String cleanEmail = email.trim();
            if (cleanEmail.startsWith("\"") && cleanEmail.endsWith("\"") && cleanEmail.length() > 1) {
                cleanEmail = cleanEmail.substring(1, cleanEmail.length() - 1);
            }
            User user = userRepository.findByEmail(cleanEmail)
                    .orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));

            String resetToken = jwtService.generateResetToken(user);
            TokenPayload resetPayload = jwtService.parseToken(resetToken, RESET_TOKEN);
            saveTokenToRedis(resetPayload, RESET_TOKEN, user.getId());

            // Gửi email
            String resetLink = "http://frontend.example.com/reset-password?token=" + resetToken;
            log.info("[FORGOT_PASSWORD] Reset link generated for {} (do not log token in prod)", cleanEmail);
            kafkaTemplate.send("notification-delivery", NotificationEvent.builder()
                    .channel("EMAIL")
                    .recipient(user.getEmail())
                    .templateCode("CHANGE_PASSWORD")
                    .param(Map.of("username", user.getUsername(), "link",
                            resetLink))
                    .subject("Thay đổi mật khẩu Devteria")
                    .build());
            return resetToken;
        }

        @Override
        public String resetPassword(String secretKey) {
            log.info("[RESET_PASSWORD]");
            TokenPayload payload = parseAndCheckToken(secretKey, RESET_TOKEN);
            if (payload.getExpiredTime().before(new Date())) {
                throw new AppException(ErrorCode.TOKEN_EXPIRED);
            }
            return "Token valid. You can now change your password.";
        }

        @Override
        public String changePassword(ResetPasswordDTO request) {
            log.info("[CHANGE_PASSWORD] for token");

            if (!request.getPassword().equals(request.getConfirmPassword())) {
                throw new AppException(ErrorCode.INVALID_PASSWORD);
            }

            TokenPayload payload = parseAndCheckToken(request.getSecretKey(), RESET_TOKEN);
            User user = getUserFromToken(request.getSecretKey(), RESET_TOKEN);

            user.setPassword(passwordEncoder.encode(request.getPassword()));
            userRepository.save(user);

            //  Xóa token khỏi Redis (dùng 1 lần)
            redisTokenRepository.deleteById(payload.getJwtId());

            log.info("[CHANGE_PASSWORD] Password changed for user={}", user.getEmail());
            return "Password changed successfully!";
        }

        @Override
        public String signUp(SignUpDTO request) {
            log.info("---------- [SIGN UP] ----------");

            if (userRepository.findByEmail((request.getEmail())).isPresent()) {
                throw new AppException(ErrorCode.EMAIL_EXISTED);
            }

            if (!request.getPassword().equals(request.getConfirmPassword())) {
                throw new AppException(ErrorCode.INVALID_PASSWORD);
            }
            User user = User.builder()
                    .email(request.getEmail())
                    .username(request.getUserName())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .roles(Set.of(getDefaultUserRole()))
                    .accountStatus(AccountStatus.LOCKED)
                    .build();
            userRepository.save(user);
            log.info("[SIGN UP] User registered: {}", user.getEmail());

            String verificationToken = jwtService.generateVerificationToken(user);
            TokenPayload payload = jwtService.parseToken(verificationToken, VERIFICATION_TOKEN);
            saveTokenToRedis(payload, VERIFICATION_TOKEN, user.getId());
            log.info("[SIGN UP] Verification token generated for {}", user.getEmail());

            //  Gửi mail xác minh
            // thay bang duong dan FE neu co
            String verifyLink = "http://localhost:8888/api/auth/verify?token=" + verificationToken;
            kafkaTemplate.send("notification-delivery", NotificationEvent.builder()
                    .channel("EMAIL")
                    .recipient(user.getEmail())
                    .templateCode("VERIFY_EMAIL")
                    .param(Map.of("username", user.getUsername(), "link",
                            verifyLink))
                    .subject("Xác nhận tài khoản Devteria")
                    .build());
            log.info("[SIGN UP] Verification email sent to {}", user.getEmail());
            return "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận.";
        }

        @Override
        public TokenResponse verifyEmail(String token) {
            log.info("[VERIFY_EMAIL] verify token");
            TokenPayload payload = parseAndCheckToken(token, VERIFICATION_TOKEN);
            User user = getUserFromToken(token, VERIFICATION_TOKEN);

            user.setAccountStatus(AccountStatus.ACTIVE);
            userRepository.save(user);
            redisTokenRepository.deleteById(payload.getJwtId());
            // Gọi sang Profile Service tạo hồ sơ mặc định
            try {
                profileClient.createUserDefaultProfile(ProfileCreationRequest.builder()
                        .userId(user.getId())
                        .email(user.getEmail())
                        .username(user.getUsername())
                        .build());
                log.info("[VERIFY_EMAIL] profile created for user={}", user.getEmail());
            } catch (Exception e) {
                log.warn("[VERIFY_EMAIL] profile creation failed for user={}, will continue login. error={}", user.getEmail(), e.getMessage());
            }
            //gui 1 thong bao cho user biet da kich hoat thanh cong
            kafkaTemplate.send("notification-delivery", NotificationEvent.builder()
                    .channel("PUSH")
                    .recipient(user.getId())
                    .templateCode("REGISTRATION_SUCCESS")
                    .param(Map.of("username", user.getUsername()))
                    .subject("Đăng ký thành công")
                    .body("Chúc mừng " + user.getUsername() + ", bạn đã đăng ký thành công!")
                    .build());
            log.info("[VERIFY_EMAIL] user {} verified successfully", user.getEmail());
            return getTokenResponse(user);
        }

        @Override
        public IntrospectResponse introspect(IntrospectRequest request) {
            try {
                var token = request.getToken();
                TokenPayload payload = jwtService.parseToken(token, TokenType.ACCESS_TOKEN);

                // Access token trong Redis = đã bị blacklist (logout)
                if (redisTokenRepository.existsById(payload.getJwtId())) {
                    log.info("[INTROSPECT] Token is blacklisted (logout): {}", payload.getJwtId());
                    return IntrospectResponse.builder().valid(false).build();
                }
                var userId = payload.getUserId();
                User user = userRepository.findById(userId)
                        .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
                // Kiểm tra token hợp lệ hay không
                boolean valid = jwtService.isValid(token, TokenType.ACCESS_TOKEN, user);
                if (!valid) {
                    log.info("[INTROSPECT] Token expired or invalid: {}", payload.getJwtId());
                    return IntrospectResponse.builder().valid(false).build();
                }
                // ✅ Kiểm tra user còn active không
                if (!user.isEnabled()) {
                    log.info("[INTROSPECT] User is not active: {}", userId);
                    return IntrospectResponse.builder().valid(false).build();
                }
                return IntrospectResponse.builder()
                        .valid(true)
                        .userId(user.getId())
                        .roles(user.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList())
                        .build();
            }
            catch (Exception e) {
                log.warn("[INTROSPECT] Token validation failed: {}", e.getMessage());
                return IntrospectResponse.builder()
                        .valid(false)
                        .build();
            }
        }
    }