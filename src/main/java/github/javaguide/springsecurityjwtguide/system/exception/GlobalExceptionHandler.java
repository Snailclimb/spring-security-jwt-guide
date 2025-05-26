package github.javaguide.springsecurityjwtguide.system.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;
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
    public ResponseEntity<ErrorResponse> handleBaseException(BaseException ex, HttpServletRequest request) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getErrorCode().getMessage(), 
                                                       ex.getErrorCode().getStatus().value(), 
                                                       request.getRequestURI());
        log.error("occur BaseException:" + errorResponse);
        return ResponseEntity.status(ex.getErrorCode().getStatus()).body(errorResponse);
    }

    /**
     * 请求参数异常处理
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        StringBuilder errorMessage = new StringBuilder("Validation failed: ");
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String message = error.getDefaultMessage();
            errorMessage.append(fieldName).append(" ").append(message).append(", ");
        });
        
        // Remove trailing comma and space
        String finalMessage = errorMessage.substring(0, errorMessage.length() - 2);
        
        ErrorResponse errorResponse = new ErrorResponse(
            finalMessage,
            HttpStatus.BAD_REQUEST.value(),
            request.getRequestURI()
        );
        
        log.error("occur MethodArgumentNotValidException:" + errorResponse);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(value = UserNameAlreadyExistException.class)
    public ResponseEntity<ErrorResponse> handleUserNameAlreadyExistException(UserNameAlreadyExistException ex, HttpServletRequest request) {
        ErrorResponse errorResponse = new ErrorResponse(
            ex.getErrorCode().getMessage(),
            ex.getErrorCode().getStatus().value(),
            request.getRequestURI()
        );
        log.error("occur UserNameAlreadyExistException:" + errorResponse);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(value = {RoleNotFoundException.class, UserNameNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(BaseException ex, HttpServletRequest request) {
        ErrorResponse errorResponse = new ErrorResponse(
            ex.getErrorCode().getMessage(),
            ex.getErrorCode().getStatus().value(),
            request.getRequestURI()
        );
        log.error("occur ResourceNotFoundException:" + errorResponse);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }
}
