package github.javaguide.springsecurityjwtguide.security.dto;

import lombok.Value;

/**
 * @author shuang.kou
 * @description 用户登录请求DTO
 */
@Value
public class LoginRequest {
    String username;
    String password;
    Boolean rememberMe;
}
