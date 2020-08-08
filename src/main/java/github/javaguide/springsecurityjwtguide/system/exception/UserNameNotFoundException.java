package github.javaguide.springsecurityjwtguide.system.exception;

import java.util.Map;

/**
 * @author shuang.kou
 */
public class UserNameNotFoundException extends BaseException {
    public UserNameNotFoundException(Map<String, Object> data) {
        super(ErrorCode.USER_NAME_NOT_FOUND, data);
    }
}
