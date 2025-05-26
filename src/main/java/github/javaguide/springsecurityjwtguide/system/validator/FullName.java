package github.javaguide.springsecurityjwtguide.system.validator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Documented
@Constraint(validatedBy = {FullNameValidator.class})
@Target({PARAMETER, FIELD})
@Retention(RUNTIME)
public @interface FullName {
    String message() default "姓名格式错误";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
