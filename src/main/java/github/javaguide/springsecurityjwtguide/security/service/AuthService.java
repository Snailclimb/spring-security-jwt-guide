package github.javaguide.springsecurityjwtguide.security.service;

import github.javaguide.springsecurityjwtguide.security.common.utils.CurrentUserUtils;
import github.javaguide.springsecurityjwtguide.security.common.utils.JwtTokenUtils;
import github.javaguide.springsecurityjwtguide.security.dto.LoginRequest;
import github.javaguide.springsecurityjwtguide.security.entity.JwtUser;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author shuang.kou
 **/
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthService {
    private final UserService userService;
    private final StringRedisTemplate stringRedisTemplate;
    private final CurrentUserUtils currentUserUtils;
    @Qualifier(value = "cacheMap")
    private final Map<String, String> cacheMap ;

    @Value("${redis.cache-switch}")
    private Boolean redisCacheSwitch;

    public String createToken(LoginRequest loginRequest) {
        User user = userService.find(loginRequest.getUsername());
        if (!userService.check(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("The user name or password is not correct.");
        }
        JwtUser jwtUser = new JwtUser(user);
        if (!jwtUser.isEnabled()) {
            throw new BadCredentialsException("User is forbidden to login");
        }
        List<String> authorities = jwtUser.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        String token = JwtTokenUtils.createToken(user.getUserName(), user.getId().toString(), authorities, loginRequest.getRememberMe());
        if (redisCacheSwitch) {
            stringRedisTemplate.opsForValue().set(user.getId().toString(), token);
        }else {
            cacheMap.put(user.getId().toString(), token);
        }

        return token;
    }

    public void removeToken() {
        if (redisCacheSwitch) {
            stringRedisTemplate.delete(currentUserUtils.getCurrentUser().getId().toString());
        }else {
            cacheMap.remove(currentUserUtils.getCurrentUser().getId().toString());
        }
    }
}
