package backend.example.identityservice.service.impl;


import backend.example.identityservice.dto.request.IntrospectRequest;
import backend.example.identityservice.dto.request.ResetPasswordDTO;
import backend.example.identityservice.dto.request.SignInRequest;
import backend.example.identityservice.dto.request.SignUpDTO;
import backend.example.identityservice.dto.response.IntrospectResponse;
import backend.example.identityservice.dto.response.TokenResponse;
import backend.example.identityservice.entity.RedisToken;
import backend.example.identityservice.entity.User;
import backend.example.identityservice.exception.AppException;
import backend.example.identityservice.exception.ErrorCode;
import backend.example.identityservice.repository.UserRepository;
import backend.example.identityservice.service.AuthenticationService;
import backend.example.identityservice.service.JwtService;
import backend.example.identityservice.service.RedisTokenService;
import backend.example.identityservice.utils.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.text.ParseException;
import java.util.stream.Collectors;

import static backend.example.identityservice.utils.TokenType.RESET_TOKEN;
import static backend.example.identityservice.utils.TokenType.VERIFICATION_TOKEN;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTokenService redisTokenService;
    private final UserService userService;
//    private final EmailService emailService;
//    private final UserMapper userMapper;


    public User findUserById(String id) {
        return userRepository.findById(id).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
    }
    @Override
    public TokenResponse accessToken(SignInRequest signInRequest) {
        log.info("-------authenticate----");
        User user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));
        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }
//
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signInRequest.getEmail(),
                            signInRequest.getPassword(),
                            user.getRoles().stream()
                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                                    .collect(Collectors.toSet())
                    )
            );
        } catch (BadCredentialsException e) {
            throw new AppException(ErrorCode.INVALID_CREDENTIALS);
        }
        log.info("Login success for user: {}", signInRequest.getEmail());
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        redisTokenService.save(RedisToken.builder()
                .id(user.getEmail())
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
        log.info("---------- refreshToken ----------");

        final String refreshToken = request.getHeader(HttpHeaders.REFERER);
        log.info("RefreshToken: {}", refreshToken);
        if (StringUtils.isBlank(refreshToken)) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }

        final String id  =jwtService.extractUsername(refreshToken, TokenType.REFRESH_TOKEN);
        log.info("id:{}", id);
        User user = userRepository.findByEmail(id).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));
        log.info("userID: {}", user.getId());

        if(!jwtService.isValid( refreshToken, TokenType.REFRESH_TOKEN, user)){
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        String accessToken = jwtService.generateToken(user);
        redisTokenService.save(RedisToken.builder()
                .id(user.getEmail())
                .refreshToken(refreshToken)
                .build());
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .build();
    }

    @Override
    public String removeToken(HttpServletRequest request) {
        log.info("---------- removeToken ----------");

        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        token = token.substring(7);
        log.info("Token: {}", token);
        if (StringUtils.isBlank(token)) {
            throw new AppException(ErrorCode.INVALID_KEY);
        }

        final String id = jwtService.extractUsername(token, TokenType.ACCESS_TOKEN);

        User user = userRepository.findByEmail(id).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));
        redisTokenService.delete(user.getId());

        return "Removed!";
    }

    @Override
    public String forgotPassword(String email) {
        log.info(email);
        email = email.trim();

        // Loại bỏ dấu ngoặc kép 2 đầu nếu có
        if (email.startsWith("\"") && email.endsWith("\"") && email.length() > 1) {
            email = email.substring(1, email.length() - 1);
        }
        log.info("---------- forgotPassword ----------");
        log.info("email: {}", email);
        // check email exists or not
        User user = userRepository.findByEmail(email).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));

        // generate reset token
        String resetToken = jwtService.generateResetToken(user);

        // save to db
        redisTokenService.save(RedisToken.builder().id(user.getEmail()).resetToken(resetToken).build());

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
        log.info("---------- resetPassword ----------");

        // validate token
        var user = validateToken(secretKey);

        // check token by email
        redisTokenService.getById(user.getEmail());

        return "Reset";
    }

    @Override
    public String changePassword(ResetPasswordDTO request) {
        log.info("---------- changePassword ----------");

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
        log.info("---------- signUp ----------");

        // Kiểm tra email đã tồn tại
        if (userRepository.findByEmail((request.getEmail())).isPresent()) {
            throw new AppException(ErrorCode.EMAIL_EXISTED);
        }

        // Kiểm tra mật khẩu khớp
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD);
        }
        User user = new User();
        user.setEmail(request.getEmail());
//        user.setFullName(request.getUserName());
//        user.setPassword(passwordEncoder.encode(request.getPassword()));
//        user.setRoles();
//        user.setRole(UserRole.USER); // Mặc định là USER
//        user.setAccountStatus(AccountStatus.LOCKED);
        String verificationToken = jwtService.generateVerificationToken(user);
        // Lưu verification token vào Token
        redisTokenService.save(RedisToken.builder()
                .id(user.getEmail())
                .verificationToken(verificationToken)
                .build());
        log.info("verify Token: {}",verificationToken);
        userRepository.save(user);
//        try {
//            emailService.sendVerificationEmail(user.getEmail(), verificationToken);
//        } catch (MessagingException e) {
//            log.error("Lỗi khi gửi email xác nhận: {}", e.getMessage());
//            throw new InvalidDataException("Không thể gửi email xác nhận");
//        }
        return "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận.";
    }

    @Override
    public String verifyEmail(String token) {
        log.info("---------- verifyEmail ----------");

        // Xác thực token
        String id = jwtService.extractUsername(token, VERIFICATION_TOKEN);
        User user = userRepository.findByEmail(id).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));

        // Kiểm tra token khớp
        if (!jwtService.isValid(token, VERIFICATION_TOKEN, user)) {
            throw new AppException(ErrorCode.VERIFICATION_TOKEN_INVALID);
        }
        // Kiểm tra token trong cơ sở dữ liệu
        RedisToken storedToken = redisTokenService.getById(user.getEmail());
        if (storedToken == null || !token.equals(storedToken.getVerificationToken())) {
            throw new AppException(ErrorCode.VERIFICATION_TOKEN_INVALID);
        }
        // Kích hoạt tài khoản
//        user.setAccountStatus(AccountStatus.ACTIVE);
        userRepository.save(user);
        // Xóa verification token khỏi Token
        redisTokenService.delete(user.getEmail());

        return "Tài khoản đã được kích hoạt thành công!";
    }

    @Override
    public IntrospectResponse introspect(IntrospectRequest request) {
        try {
            var token = request.getToken();
            String id = jwtService.extractUsername(token, TokenType.ACCESS_TOKEN);
            // Load user từ DB
            UserDetails user = userService.loadUserByUsername(id);

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
        // validate token
        var id = jwtService.extractUsername(token, RESET_TOKEN);

        // validate user is active or not
        User user = userRepository.findByEmail(id).orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOT_FOUND));
        if (!user.isEnabled()) {
            throw new AppException(ErrorCode.USER_NOT_ACTIVE);
        }

        return user;
    }
}