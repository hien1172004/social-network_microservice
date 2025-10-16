package backend.example.identityservice.service.impl;

import backend.example.identityservice.dto.TokenPayload;
import backend.example.identityservice.entity.User;
import backend.example.identityservice.exception.AppException;
import backend.example.identityservice.exception.ErrorCode;
import backend.example.identityservice.service.JwtService;
import backend.example.identityservice.utils.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import static backend.example.identityservice.utils.TokenType.VERIFICATION_TOKEN;


@Service
@Slf4j
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {
    @Value(("${jwt.expiryHour}"))
    private long expiryHour;

    @Value(("${jwt.expiryDay}"))
    private long expiryDay;

    @Value(("${jwt.secretKey}"))
    private String secretKey;

    @Value(("${jwt.refreshKey}"))
    private String refreshKey;

    @Value(("${jwt.resetKey}"))
    private String resetKey;

    @Value(("${jwt.verifyKey}"))
    private String verifyKey;



    // ------------------- Generate Tokens -------------------

    private String generateToken(Map<String, Object> claims, User user, TokenType type, long durationMs) {
        return Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setSubject(user.getId())              // sub = userId
                .claim("username", user.getUsername())
                .claim("email", user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + durationMs))
                .signWith(getKey(type), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String generateToken(User user) {
        return generateToken(new HashMap<>(), user, TokenType.ACCESS_TOKEN, 1000 * 60 * 60 * 24 * expiryHour);
    }

    @Override
    public String generateRefreshToken(User user) {
        return generateToken(new HashMap<>(), user, TokenType.REFRESH_TOKEN, 1000 * 60 * 60 * 24 * expiryDay);
    }

    @Override
    public String generateResetToken(User user) {
        return generateToken(new HashMap<>(), user, TokenType.RESET_TOKEN, 1000 * 60 * 60);
    }

    @Override
    public String generateVerificationToken(User user) {
        return generateToken(new HashMap<>(), user, VERIFICATION_TOKEN, 1000 * 60 * 60 * 24); // 24h
    }

    // ------------------- Validate / Extract Claims -------------------

    private Key getKey(TokenType type) {
        switch (type) {
            case ACCESS_TOKEN -> { return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)); }
            case REFRESH_TOKEN -> { return Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshKey)); }
            case RESET_TOKEN -> { return Keys.hmacShaKeyFor(Decoders.BASE64.decode(resetKey)); }
            case VERIFICATION_TOKEN -> { return Keys.hmacShaKeyFor(Decoders.BASE64.decode(verifyKey)); }
            default -> throw new AppException(ErrorCode.INVALID_KEY);
        }
    }
    private Claims extractAllClaims(String token, TokenType type) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getKey(type))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
    }
    private <T> T extractClaim(String token, TokenType type, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token, type);
        return claimsResolver.apply(claims);
    }
    @Override
    public String extractUserId(String token, TokenType type) {
        return extractClaim(token, type, Claims::getSubject); // sub = userId
    }

    @Override
    public String extractUsername(String token, TokenType type) {
        return extractClaim(token, type, claims -> claims.get("username", String.class));
    }

    @Override
    public String extractEmail(String token, TokenType type) {
        return extractClaim(token, type, claims -> claims.get("email", String.class));
    }
    @Override
    public String extractJwtId(String token, TokenType type) {
        return extractClaim(token, type, Claims::getId);
    }

    private boolean isTokenExpired(String token, TokenType type) {
        Date expiration = extractClaim(token, type, Claims::getExpiration);
        return expiration != null && expiration.before(new Date());
    }

    @Override
    public boolean isValid(String token, TokenType type, User user) {
        final String userId = extractUserId(token, type);
        return userId.equals(user.getId()) && !isTokenExpired(token, type);
    }
    @Override
    public TokenPayload parseToken(String token, TokenType type) {
        Claims claims = extractAllClaims(token, type);
        return TokenPayload.builder()
                .token(token)
                .jwtId(claims.getId())
                .expiredTime(claims.getExpiration())
                .build();
    }
}
