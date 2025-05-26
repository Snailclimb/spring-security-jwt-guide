package github.javaguide.springsecurityjwtguide.security.service;

import github.javaguide.springsecurityjwtguide.security.common.utils.CurrentUserUtil;
import github.javaguide.springsecurityjwtguide.security.common.utils.JwtTokenUtil;
import github.javaguide.springsecurityjwtguide.security.dto.LoginRequest;
import github.javaguide.springsecurityjwtguide.security.entity.JwtUser;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.exception.UserNameNotFoundException;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author shuang.kou
 **/
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class AuthService {
    private final UserService userService;
    private final StringRedisTemplate stringRedisTemplate;
    private final CurrentUserUtil currentUserUtil;

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
        String token = JwtTokenUtil.createToken(user.getUserName(), user.getId().toString(), authorities, loginRequest.getRememberMe());
        stringRedisTemplate.opsForValue().set(user.getId().toString(), token);
        return token;
    }

    public void removeToken() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                log.warn("No authenticated user found for logout");
                return;
            }
            
            User currentUser = currentUserUtil.getCurrentUser();
            if (currentUser != null && currentUser.getId() != null) {
                String userId = currentUser.getId().toString();
                log.info("Removing token for user ID: {}", userId);
                Boolean deleted = stringRedisTemplate.delete(userId);
                log.info("Token deletion result: {}", deleted);
            } else {
                log.warn("User ID is null, cannot remove token");
            }
        } catch (UserNameNotFoundException ex) {
            log.error("User not found during logout: {}", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            log.error("Error during logout: {}", ex.getMessage());
            throw ex;
        }
    }
}
