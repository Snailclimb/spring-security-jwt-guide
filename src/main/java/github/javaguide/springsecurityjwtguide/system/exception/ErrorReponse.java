package github.javaguide.springsecurityjwtguide.system.exception;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.util.ObjectUtils;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Getter
@ToString
@NoArgsConstructor
public class ErrorReponse {
    private int code;
    private int status;
    private String message;
    private String path;
    private Instant timestamp;
    private HashMap<String, Object> data = new HashMap<>();

    public ErrorReponse(BaseException ex, String path) {
        this(ex.getErrorCode().getCode(), ex.getErrorCode().getStatus().value(), ex.getErrorCode().getMessage(), path, ex.getData());
    }

    public ErrorReponse(ErrorCode errorCode, String path) {
        this(errorCode.getCode(), errorCode.getStatus().value(), errorCode.getMessage(), path, null);
    }

    public ErrorReponse(int code, int status, String message, String path, Map<String, Object> data) {
        this.code = code;
        this.status = status;
        this.message = message;
        this.path = path;
        this.timestamp = Instant.now();
        if (!ObjectUtils.isEmpty(data)) {
            this.data.putAll(data);
        }
    }
}
