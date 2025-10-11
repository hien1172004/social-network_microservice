package backend.example.identityservice.config;

    import com.fasterxml.jackson.databind.ObjectMapper;
    import com.fasterxml.jackson.databind.SerializationFeature;
    import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
    import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
    import org.springframework.data.redis.core.HashOperations;
    import org.springframework.data.redis.core.RedisTemplate;
    import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;

    @Configuration
    public class RedisConfig {
        @Value("${spring.data.redis.host}")
        private String redisHost;
        @Value("${spring.data.redis.port}")
        private String redisPort;

        @Bean
        JedisConnectionFactory jedisConnectionFactory() {
            RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
            redisStandaloneConfiguration.setHostName(redisHost);
            redisStandaloneConfiguration.setPort(Integer.parseInt(redisPort));

            return new JedisConnectionFactory(redisStandaloneConfiguration);
        }


        @Bean
        public ObjectMapper redisObjectMapper() {
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            return mapper;
        }

        @Bean
        <K, V> RedisTemplate<K, V> redisTemplate(ObjectMapper redisObjectMapper) {
            RedisTemplate<K, V> redisTemplate = new RedisTemplate<>();

            redisTemplate.setConnectionFactory(jedisConnectionFactory());
            GenericJackson2JsonRedisSerializer serializer = new GenericJackson2JsonRedisSerializer(redisObjectMapper);
            redisTemplate.setKeySerializer(serializer);
            redisTemplate.setHashKeySerializer(serializer);
            redisTemplate.setValueSerializer(serializer);
            redisTemplate.setHashValueSerializer(serializer);

            return redisTemplate;
        }

        @Bean
        <K, F, V> HashOperations<K, F, V> hashOperations(RedisTemplate<K, V> redisTemplate) {
            return redisTemplate.opsForHash();
        }
    }