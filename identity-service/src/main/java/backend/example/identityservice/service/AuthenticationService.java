package backend.example.identityservice.service;


import backend.example.identityservice.dto.request.IntrospectRequest;
import backend.example.identityservice.dto.request.ResetPasswordDTO;
import backend.example.identityservice.dto.request.SignInRequest;
import backend.example.identityservice.dto.request.SignUpDTO;
import backend.example.identityservice.dto.response.IntrospectResponse;
import backend.example.identityservice.dto.response.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;


public interface AuthenticationService {
    TokenResponse accessToken(SignInRequest signInRequest);

    TokenResponse refreshToken(HttpServletRequest request);

    String removeToken(HttpServletRequest request);

    String forgotPassword(String email);

    String resetPassword(String secretKey);

    String changePassword(ResetPasswordDTO request);

    String signUp(SignUpDTO request);

    String verifyEmail(String token);

    IntrospectResponse introspect(IntrospectRequest request);

}