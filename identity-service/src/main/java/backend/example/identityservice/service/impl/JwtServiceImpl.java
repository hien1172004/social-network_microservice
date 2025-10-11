package backend.example.identityservice.service.impl;

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


    private String generateToken(Map<String, Object> claims, UserDetails userDetails){
        if (userDetails instanceof backend.example.identityservice.entity.User appUser) {
            claims.put("userId", appUser.getId());
            claims.put("email", appUser.getEmail());
            claims.put("roles", appUser.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList());
        }
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date((System.currentTimeMillis()) + 1000 * 60 * 60 * 24 * expiryHour))
                .signWith(getKey(TokenType.ACCESS_TOKEN), SignatureAlgorithm.HS256)
                .compact();
    }

    private String generateRefreshToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date((System.currentTimeMillis()) + 1000 * 60 * 60 * 24 * expiryDay))
                .signWith(getKey(TokenType.REFRESH_TOKEN), SignatureAlgorithm.HS256)
                .compact();
    }

    private String generateResetToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date((System.currentTimeMillis()) + 1000 * 60 * 60))
                .signWith(getKey(TokenType.RESET_TOKEN), SignatureAlgorithm.HS256)
                .compact();
    }
    private String generateVerificationToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .signWith(getKey(VERIFICATION_TOKEN), SignatureAlgorithm.HS256)
                .compact();
    }
    private Key getKey(TokenType type){
        switch (type){
            case ACCESS_TOKEN -> {return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));}
            case REFRESH_TOKEN -> {return Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshKey));}
            case RESET_TOKEN -> {return Keys.hmacShaKeyFor(Decoders.BASE64.decode(resetKey));}
            case VERIFICATION_TOKEN -> {return Keys.hmacShaKeyFor(Decoders.BASE64.decode(verifyKey));}
            default -> throw new AppException(ErrorCode.INVALID_KEY);
        }
    }
    private <T> T extractClaim(String token, TokenType type, Function<Claims, T> claimsResolver){
        final Claims claims = extraAllClaim(token, type);
        return claimsResolver.apply(claims);
    }

    private Claims extraAllClaim(String token, TokenType type){
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
    private boolean isTokenExpired(String token, TokenType type) {
        Date expiration = extractExpiration(token, type);
        return expiration != null && expiration.before(new Date());
    }

    private Date extractExpiration(String token, TokenType type) {
        return extractClaim(token, type, Claims::getExpiration);
    }

    @Override
    public String generateToken(UserDetails user) {
        return generateToken(new HashMap<>(), user);
    }

    @Override
    public String extractUsername(String token, TokenType type) {
        return extractClaim(token, type, Claims::getSubject);
    }

    @Override
    public boolean isValid(String token, TokenType type, UserDetails userDetails) {
        log.info("---------- isValid ----------");
        log.info("Checking token validity: type={}, id={}", type, userDetails.getUsername());
        final String id = extractUsername(token, type);
        return (id.equals(userDetails.getUsername()) && !isTokenExpired(token, type));
    }

    @Override
    public String generateRefreshToken(UserDetails user) {
        return generateRefreshToken(new HashMap<>(), user);
    }

    @Override
    public String generateResetToken(UserDetails user) {
        return generateResetToken(new HashMap<>(), user);
    }

    @Override
    public String generateVerificationToken(UserDetails user) {
        return generateVerificationToken(new HashMap<>(), user);
    }
}
