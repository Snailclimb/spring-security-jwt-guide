package github.javaguide.springsecurityjwtguide.system.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * @author shuang.kou
 * @createTime 2020年08月08日 20:57:00
 **/
public class LoginFailedException extends AuthenticationException {
    public LoginFailedException(String detail) {
        super(detail);
    }
}
