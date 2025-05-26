package github.javaguide.springsecurityjwtguide.system;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@SpringBootTest
@ExtendWith(SpringExtension.class)
public class RedisTest {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    
    @Test
    public void testRedis() {
        // 保存字符串
        stringRedisTemplate.opsForValue().set("test", "hello redis");
        System.out.println(stringRedisTemplate.opsForValue().get("test"));
    }
}