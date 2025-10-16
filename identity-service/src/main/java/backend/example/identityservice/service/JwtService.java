package backend.example.identityservice.service;

import backend.example.identityservice.dto.TokenPayload;
import backend.example.identityservice.entity.User;
import backend.example.identityservice.utils.TokenType;



public interface JwtService {
    // ------------------- Generate Tokens -------------------
    String generateToken(User user);                     // Access token
    String generateRefreshToken(User user);              // Refresh token
    String generateResetToken(User user);                // Reset password token
    String generateVerificationToken(User user);         // Email verification token

    // ------------------- Extract Claims -------------------
    String extractUserId(String token, TokenType type);   // Lấy sub = userId
    String extractUsername(String token, TokenType type); // Lấy username từ claim
    String extractEmail(String token, TokenType type);    // Lấy email từ claim
    String extractJwtId(String token, TokenType type);     // Lấy jti từ claim
    // ------------------- Validate Token -------------------
    boolean isValid(String token, TokenType type, User user);
    TokenPayload parseToken(String token, TokenType type);
}
