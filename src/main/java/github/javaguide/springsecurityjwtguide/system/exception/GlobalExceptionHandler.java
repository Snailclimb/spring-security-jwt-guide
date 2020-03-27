package github.javaguide.springsecurityjwtguide.system.exception;

import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * @author shuang.kou
 */
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(value = UserNameAlreadyExistException.class)
    public ResponseEntity<ErrorMessage> handleUserNameAlreadyExistException(UserNameAlreadyExistException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), e.getMessage()));
    }
    @ExceptionHandler(value = SignatureException.class)
    public ResponseEntity<ErrorMessage> handleSignatureException(SignatureException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(HttpStatus.UNAUTHORIZED.value(), e.getMessage()));
    }
}
