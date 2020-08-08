package github.javaguide.springsecurityjwtguide.system.exception;

import java.util.Map;

/**
 * @author shuang.kou
 */
public class RoleNotFoundException extends BaseException {
    public RoleNotFoundException(Map<String, Object> data) {
        super(ErrorCode.Role_NOT_FOUND, data);
    }
}
