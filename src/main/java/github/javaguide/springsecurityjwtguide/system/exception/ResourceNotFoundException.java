package github.javaguide.springsecurityjwtguide.system.exception;

import java.util.Map;

/**
 * @author shuang.kou
 */
public class ResourceNotFoundException extends BaseException {
    public ResourceNotFoundException(Map<String, Object> data) {
        super(ErrorCode.NOT_FOUND, data);
    }
}
