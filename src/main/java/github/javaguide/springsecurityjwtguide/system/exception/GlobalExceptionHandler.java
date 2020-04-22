package github.javaguide.springsecurityjwtguide.system.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;


/**
 * @author shuang.kou
 */
@ControllerAdvice
@ResponseBody
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<?> handleBaseException(BaseException ex, HttpServletRequest request) {
        ErrorReponse errorReponse = new ErrorReponse(ex, request.getRequestURI());
        log.error("occur BaseException:" + errorReponse.toString());
        return ResponseEntity.status(ex.getErrorCode().getStatus()).body(errorReponse);
    }

    /**
     * 请求参数异常处理
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, Object> errors = new HashMap<>(8);
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        ErrorReponse errorReponse = new ErrorReponse(ErrorCode.METHOD_ARGUMENT_NOT_VALID, request.getRequestURI(), errors);
        log.error("occur MethodArgumentNotValidException:" + errorReponse.toString());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorReponse);
    }

    @ExceptionHandler(value = UserNameAlreadyExistException.class)
    public ResponseEntity<ErrorReponse> handleUserNameAlreadyExistException(UserNameAlreadyExistException ex, HttpServletRequest request) {
        ErrorReponse errorReponse = new ErrorReponse(ex, request.getRequestURI());
        log.error("occur UserNameAlreadyExistException:" + errorReponse.toString());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorReponse);
    }

    @ExceptionHandler(value = ResourceNotFoundException.class)
    public ResponseEntity<ErrorReponse> handleUserNotFoundException(ResourceNotFoundException ex, HttpServletRequest request) {
        ErrorReponse errorReponse = new ErrorReponse(ex, request.getRequestURI());
        log.error("occur ResourceNotFoundException:" + errorReponse.toString());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorReponse);
    }
}
