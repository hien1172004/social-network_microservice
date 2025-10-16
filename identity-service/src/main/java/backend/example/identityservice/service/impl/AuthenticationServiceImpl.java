    package backend.example.identityservice.service.impl;

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
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.stereotype.Service;

    import java.util.Date;
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

        private void saveTokenToRedis(TokenPayload payload) {
            long ttl = (payload.getExpiredTime().getTime() - System.currentTimeMillis()) / 1000;
            redisTokenRepository.save(RedisToken.builder()
                    .jwtId(payload.getJwtId())
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
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            saveTokenToRedis(jwtService.parseToken(refreshToken, TokenType.REFRESH_TOKEN));

            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(user.getId())
                    .build();
        }

        @Override
        public TokenResponse refreshToken(HttpServletRequest request) {
            log.info("[REFRESH_TOKEN] Requesting refresh token");

            String refreshToken = extractBearerToken(request);
            TokenPayload oldPayload = parseAndCheckToken(refreshToken, TokenType.REFRESH_TOKEN);
            User user = getUserFromToken(refreshToken, TokenType.REFRESH_TOKEN);

            redisTokenRepository.deleteById(oldPayload.getJwtId());

            String newAccessToken = jwtService.generateToken(user);
            String newRefreshToken = jwtService.generateRefreshToken(user);
            saveTokenToRedis(jwtService.parseToken(newRefreshToken, TokenType.REFRESH_TOKEN));

            return TokenResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .userId(user.getId())
                    .build();
        }

        @Override
        public String removeToken(HttpServletRequest request) {
            log.info("[REMOVE_TOKEN] Logout request");
            String token = extractBearerToken(request);
            TokenPayload payload = jwtService.parseToken(token, TokenType.ACCESS_TOKEN);
            if (payload.getExpiredTime().before(new Date())) {
                throw new AppException(ErrorCode.TOKEN_EXPIRED);
            }
            // Mark token as revoked
            saveTokenToRedis(payload);
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
            saveTokenToRedis(jwtService.parseToken(resetToken, RESET_TOKEN));

            // Gửi email
            String resetLink = String.format("%s/reset-password?token=%s", /*frontend*/ "https://frontend.example.com", resetToken);
            log.info("[FORGOT_PASSWORD] Reset link generated for {} (do not log token in prod)", cleanEmail);
            // emailService.sendResetPasswordEmail(cleanEmail, resetLink);
    //        // Gửi email chứa liên kết đặt lại mật khẩu
    //        try {
    //            emailService.sendResetPasswordEmail(user.getEmail(), resetToken);
    //        } catch (MessagingException e) {
    //            log.error("Lỗi khi gửi email đặt lại mật khẩu: {}", e.getMessage());
    //            throw new InvalidDataException("Không thể gửi email đặt lại mật khẩu");
    //        }
            String confirmLink = String.format("""
                    curl --location 'http://localhost:8080/auth/reset-password' \\
                    --header 'accept: */*' \\
                    --header 'Content-Type: application/json' \\
                    --data '%s'""", resetToken);
            log.info("--> confirmLink: {}", confirmLink);

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
            saveTokenToRedis(jwtService.parseToken(verificationToken, VERIFICATION_TOKEN));
            log.info("[SIGN UP] Verification token generated for {}", user.getEmail());

            // 6️⃣ (Tùy chọn) Gửi mail xác minh
            String verifyLink = "http://frontend-domain/verify?token=" + verificationToken;
            log.info("Verification link: {}", verifyLink);
            // emailService.sendVerificationEmail(user.getEmail(), verifyLink);
    //        try {
    //            emailService.sendVerificationEmail(user.getEmail(), verificationToken);
    //        } catch (MessagingException e) {
    //            log.error("Lỗi khi gửi email xác nhận: {}", e.getMessage());
    //            throw new InvalidDataException("Không thể gửi email xác nhận");
    //        }
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

            // Tự động đăng nhập — sinh Access Token & Refresh Token
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            saveTokenToRedis(jwtService.parseToken(refreshToken, TokenType.REFRESH_TOKEN));
            //***gui 1 thong bao cho user biet da kich hoat thanh cong


            log.info("[VERIFY_EMAIL] user {} verified successfully", user.getEmail());
            //rả về TokenResponse cho FE
            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(user.getId())
                    .build();
        }

        @Override
        public IntrospectResponse introspect(IntrospectRequest request) {
            try {
                var token = request.getToken();
                String email = jwtService.extractEmail(token, TokenType.ACCESS_TOKEN);
                User user = userRepository.findByEmail(email)
                        .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

                // Kiểm tra token hợp lệ hay không
                boolean valid = jwtService.isValid(token, TokenType.ACCESS_TOKEN, user);
                return IntrospectResponse.builder()
                        .valid(valid)
                        .build();
            }
            catch (AppException e) {
                return IntrospectResponse.builder()
                        .valid(false)
                        .build();
            }
        }
    }