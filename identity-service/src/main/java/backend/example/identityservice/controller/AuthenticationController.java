package backend.example.identityservice.controller;


import backend.example.identityservice.dto.request.*;
import backend.example.identityservice.dto.response.IntrospectResponse;
import backend.example.identityservice.dto.response.TokenResponse;
import backend.example.identityservice.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@Slf4j
@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ApiResponse<TokenResponse> accessToken(@RequestBody SignInRequest request) {
        return ApiResponse.
                <TokenResponse>builder()
                .result(authenticationService.accessToken(request))
                .build();
    }

    @PostMapping("/refresh-token")
    public ApiResponse<TokenResponse> refreshToken(HttpServletRequest request) {
        return ApiResponse
                .<TokenResponse>builder()
                .result(authenticationService.refreshToken(request))
                .build();
    }
    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> authenticate(@RequestBody IntrospectRequest request) {
        var result = authenticationService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder().result(result).build();
    }

    @PostMapping("/logout")
    public ApiResponse<String> removeToken(HttpServletRequest request) {
        return ApiResponse.<String>builder()
                .result(authenticationService.removeToken(request))
                .build();
    }

    @PostMapping("/forgot-password")
    public ApiResponse<String> forgotPassword(@RequestBody String email) {
        return ApiResponse.<String>builder()
                .result(authenticationService.forgotPassword(email))
                .build();
    }

    @GetMapping("/reset-password")
    public ApiResponse<String> resetPassword(@RequestParam String token) {
        return ApiResponse.<String>builder()
                .result(authenticationService.resetPassword(token))
                .build();
    }

    @PostMapping("/change-password")
    public ApiResponse<String> changePassword(@RequestBody @Valid ResetPasswordDTO request) {
        return ApiResponse.<String>builder()
                .result(authenticationService.changePassword(request))
                .build();
    }

    @PostMapping("/register")
    public ApiResponse<String> signUp(@RequestBody @Valid SignUpDTO request) {
        log.info("Signing up new user with email: {}", request.getEmail());
        String message = authenticationService.signUp(request);
        return ApiResponse.<String>builder()
                .result(message)
                .build();
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam("token") String token) {
        log.info("Verifying email with token: {}", token);

        TokenResponse tokenResponse = authenticationService.verifyEmail(token);

        //  URL FE mà bạn muốn redirect về (đổi lại theo domain của bạn)
        String redirectUrl = String.format(
                "https://yourfrontend.com/auth/success?accessToken=%s&refreshToken=%s",
                tokenResponse.getAccessToken(),
                tokenResponse.getRefreshToken()
        );

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectUrl))
                .build();
    }
}