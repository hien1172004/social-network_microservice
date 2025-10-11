package backend.example.identityservice.service;

import backend.example.identityservice.entity.RedisToken;
import backend.example.identityservice.exception.AppException;
import backend.example.identityservice.exception.ErrorCode;
import backend.example.identityservice.repository.RedisTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class RedisTokenService {
    private final RedisTokenRepository redisTokenRepository;

    public String save(RedisToken redisToken) {
        RedisToken result =  redisTokenRepository.save(redisToken);
        return result.getId();
    }

    public void delete(String id) {
        redisTokenRepository.deleteById(id);
    }

    public RedisToken getById(String email) {
        return  redisTokenRepository.findById(email).orElseThrow(()-> new AppException(ErrorCode.EMAIL_NOT_FOUND));
    }
}