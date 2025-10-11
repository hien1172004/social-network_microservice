package backend.example.identityservice.service;

import backend.example.identityservice.utils.TokenType;
import org.springframework.security.core.userdetails.UserDetails;


public interface JwtService {
    String generateToken(UserDetails user);

    String extractUsername(String token, TokenType type);

    boolean isValid(String token, TokenType type, UserDetails userDetails);

    String generateRefreshToken(UserDetails user);

    String generateResetToken(UserDetails userDetails);

    String generateVerificationToken(UserDetails userDetails);
}
