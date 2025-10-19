package backend.example.identityservice.entity;

import backend.example.identityservice.utils.TokenType;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@RedisHash(value = "RedisToken")
public class RedisToken implements Serializable {
    @Id
    private String jwtId;

    @Indexed
    private String userId;

    @Indexed
    private TokenType tokenType;

    @TimeToLive
    private Long expiration; // in seconds
}