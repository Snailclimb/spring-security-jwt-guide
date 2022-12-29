package github.javaguide.springsecurityjwtguide.system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Configuration
public class MemoryConfig {

    @Bean(name = "cacheMap")
    public Map<String, String> cacheMap(){
        return new HashMap<>();
    }
}
