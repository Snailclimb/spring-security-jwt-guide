package github.javaguide.springsecurityjwtguide.security.common.utils;

import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.exception.UserNameNotFoundException;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * @author shuang.kou
 * @description 获取当前请求的用户
 */
@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class CurrentUserUtil {

    private final UserService userService;

    public User getCurrentUser() {
        String username = getCurrentUserName();
        if (username == null || username.isEmpty()) {
            log.error("No username found in security context");
            Map<String, Object> data = new HashMap<>();
            data.put("message", "未找到当前用户信息，请确认已登录");
            throw new UserNameNotFoundException(data);
        }
        log.info("Getting current user with username: {}", username);
        return userService.find(username);
    }

    private String getCurrentUserName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() != null) {
            log.info("Authentication principal: {}, type: {}", 
                     authentication.getPrincipal(), 
                     authentication.getPrincipal().getClass().getName());
            return (String) authentication.getPrincipal();
        }
        return null;
    }
}
