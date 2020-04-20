package github.javaguide.springsecurityjwtguide.system.exception;

import java.util.Map;

/**
 * @author shuang.kou
 */
public class NotFoundException extends BaseException {
    public NotFoundException(Map<String, Object> data) {
        super(ErrorCode.NOT_FOUND, data);
    }
}
