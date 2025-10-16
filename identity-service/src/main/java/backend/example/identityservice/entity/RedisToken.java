package backend.example.identityservice.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@RedisHash(value = "RedisToken") // TTL = 0 => set động trong service
public class RedisToken implements Serializable {
    @Id
    private String id;
    private String accessToken;
    private String refreshToken;
    private String resetToken;
    private String verificationToken;

    @TimeToLive
    private Long ttl;
}