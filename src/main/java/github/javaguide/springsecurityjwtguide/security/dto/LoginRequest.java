package github.javaguide.springsecurityjwtguide.security.dto;

import lombok.Data;


/**
 * @author shuang.kou
 */
@Data
public class LoginRequest {
    private String username;
    private String password;
    private Boolean rememberMe;
}
