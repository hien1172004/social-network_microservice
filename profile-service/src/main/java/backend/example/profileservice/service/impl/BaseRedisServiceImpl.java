package backend.example.profileservice.service.impl;


import backend.example.profileservice.service.BaseRedisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class BaseRedisServiceImpl<K, F, V> implements BaseRedisService<K, F, V> {
    private final RedisTemplate<K, V> redisTemplate;
    private final HashOperations<K, F, V> hashOperations;

    @Override
    public void set(K key, V value) {
        redisTemplate.opsForValue().set(key, value);
    }

    @Override
    public void setTimeToLive(K key, long timoutInSeconds) {
        redisTemplate.expire(key,timoutInSeconds, TimeUnit.SECONDS);
    }

    @Override
    public void hashset(K key, F field, V value) {
        hashOperations.put(key, field, value);
    }

    @Override
    public boolean hashExists(K key, F field) {
        return  hashOperations.hasKey(key, field);
    }

    @Override
    public V get(K key) {
        return redisTemplate.opsForValue().get(key);
    }

    @Override
    public Map<F, V> getField(K key) {
        return hashOperations.entries(key);
    }

    @Override
    public V hashGet(K key, F field) {
        return hashOperations.get(key, field);
    }

    @Override
    public List<V> hashGetByFieldPrefix(K key, String fieldPrefix) {
        List<V> result = new ArrayList<>();
        Map<F, V> hashMap = hashOperations.entries(key);

        for (Map.Entry<F, V> entry : hashMap.entrySet()) {
            if (entry.getKey() instanceof String fieldStr && fieldStr.startsWith(fieldPrefix)) {
                result.add(entry.getValue());
            }
        }

        return result;
    }

    @Override
    public Set<F> getFieldPrefixes(K key) {
       return hashOperations.entries(key).keySet();
    }

    @Override
    public void delete(K key) {
        redisTemplate.delete(key);
    }

    @Override
    public void delete(K key, F field) {
        hashOperations.delete(key, field);
    }

    @Override
    public void delete(K key, List<F> fields) {
        hashOperations.delete(key, fields.toArray());
    }
}