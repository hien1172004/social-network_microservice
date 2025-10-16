package backend.example.identityservice.service.impl;

import backend.example.identityservice.dto.request.*;
import backend.example.identityservice.dto.response.IntrospectResponse;
import backend.example.identityservice.dto.response.TokenResponse;
import backend.example.identityservice.entity.RedisToken;
import backend.example.identityservice.entity.Role;
import backend.example.identityservice.entity.User;
import backend.example.identityservice.exception.AppException;
import backend.example.identityservice.exception.ErrorCode;
import backend.example.identityservice.repository.RoleRepository;
import backend.example.identityservice.repository.UserRepository;
import backend.example.identityservice.repository.httpClient.ProfileClient;
import backend.example.identityservice.service.AuthenticationService;
import backend.example.identityservice.service.JwtService;
import backend.example.identityservice.service.RedisTokenService;
import backend.example.identityservice.utils.AccountStatus;
import backend.example.identityservice.utils.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.stream.Collectors;
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
    RedisTokenService redisTokenService;
    RoleRepository roleRepository;
    ProfileClient profileClient;


    /**
     * Extract Bearer token from Authorization header.
     */
    private String extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(header) || !header.startsWith("Bearer ")) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }
        return header.substring(7);
    }

    /**
     * Validate JWT for given user + type.
     * Throws AppException if invalid.
     */
    private void validateJwtToken(String token, TokenType type, User user) {
        if (!jwtService.isValid(token, type, user)) {
            throw new AppException(
                    type == VERIFICATION_TOKEN ? ErrorCode.VERIFICATION_TOKEN_INVALID : ErrorCode.UNAUTHENTICATED
            );
        }
    }

    // -------------------- AUTH ENDPOINTS --------------------
    @Override
    public TokenResponse accessToken(SignInRequest signInRequest) {
        log.info("[ACCESS_TOKEN] Authenticate user: {}", signInRequest.getUsername());
        User user = userRepository.findByUsername(signInRequest.getUsername()).
                orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signInRequest.getUsername(),
                            signInRequest.getPassword(),
                            user.getRoles().stream()
                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                                    .collect(Collectors.toSet())
                    )
            );
        } catch (BadCredentialsException e) {
            log.warn("[ACCESS_TOKEN] Bad credentials for user {}", signInRequest.getUsername());
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }
        log.info("[ACCESS_TOKEN] Login success for user: {}", signInRequest.getUsername());
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        redisTokenService.save(RedisToken.builder()
                .id(user.getId())
                .refreshToken(refreshToken)
                .build());
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .build();
    }

    @Override
    public TokenResponse refreshToken(HttpServletRequest request) {
        log.info("[REFRESH_TOKEN] Requesting refresh token");

        final String refreshToken = extractBearerToken(request);

        String userId = jwtService.extractUserId(refreshToken, TokenType.REFRESH_TOKEN);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        log.info("userID: {}", user.getId());

        // Validate signature + expiration
        validateJwtToken(refreshToken, TokenType.REFRESH_TOKEN, user);

        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        redisTokenService.save(RedisToken.builder()
                .id(user.getId())
                        .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build());
        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .userId(user.getId())
                .build();
    }

    @Override
    public String removeToken(HttpServletRequest request) {
        log.info("[REMOVE_TOKEN] Logout request");

        final String token = extractBearerToken(request);

        String userId = jwtService.extractUserId(token, TokenType.ACCESS_TOKEN);
        redisTokenService.delete(userId);

        return "Removed!";
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
        // save to db
        redisTokenService.save(RedisToken.builder()
                .id(user.getId())
                .resetToken(resetToken)
                .build());
        // Build reset link and send mail (emailService commented out for now)
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

        // validate token
        var user = validateToken(secretKey);

        // check token
        redisTokenService.getById(user.getUsername());

        return "Reset OK";
    }

    @Override
    public String changePassword(ResetPasswordDTO request) {
        log.info("[CHANGE_PASSWORD] for token");

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD);
        }

        // get user by reset token
        var user = validateToken(request.getSecretKey());

        // update password
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        return "Changed";
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
        // Lấy role mặc định
        Role userRole = roleRepository.findById("USER")
                .orElseGet(() -> {
                    Role newRole = Role.builder()
                            .name("USER")
                            .description("Default role for normal users")
                            .build();
                    return roleRepository.save(newRole);
                });
        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUserName())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .accountStatus(AccountStatus.LOCKED)
                .build();
        String verificationToken = jwtService.generateVerificationToken(user);
        userRepository.save(user);

        redisTokenService.save(RedisToken.builder()
                .id(user.getId())
                .verificationToken(verificationToken)
                .build());
        log.info("verify Token: {}",verificationToken);

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
        log.info("[VERIFY_EMAIL] verify token (not logging token)");
        String id = jwtService.extractUserId(token, VERIFICATION_TOKEN);
        User user = userRepository.findById(id).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        if (!jwtService.isValid(token, VERIFICATION_TOKEN, user)) {
            throw new AppException(ErrorCode.VERIFICATION_TOKEN_INVALID);
        }
        RedisToken storedToken = redisTokenService.getById(user.getId());
        if (storedToken == null || !token.equals(storedToken.getVerificationToken())) {
            throw new AppException(ErrorCode.VERIFICATION_TOKEN_INVALID);
        }
        user.setAccountStatus(AccountStatus.ACTIVE);
        userRepository.save(user);
        redisTokenService.delete(user.getId());
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

        // Lưu refresh token vào Redis
        redisTokenService.save(RedisToken.builder()
                .id(user.getId())
                .refreshToken(refreshToken)
                .build());
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

    private User validateToken(String token) {
        String userId = jwtService.extractUserId(token, RESET_TOKEN);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }

        return user;
    }
}