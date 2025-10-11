package backend.example.identityservice.entity;

import lombok.*;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@RedisHash("RedisToken")
public class RedisToken implements Serializable {
    private String id;
    private String accessToken;
    private String refreshToken;
    private String resetToken;
    private String verificationToken;
}