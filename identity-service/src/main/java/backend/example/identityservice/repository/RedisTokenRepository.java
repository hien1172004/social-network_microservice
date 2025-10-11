package backend.example.identityservice.repository;

import backend.example.identityservice.entity.RedisToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RedisTokenRepository  extends CrudRepository<RedisToken, String> {
}