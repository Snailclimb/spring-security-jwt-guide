package github.javaguide.springsecurityjwtguide.system.validator;


import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class FullNameValidator implements ConstraintValidator<FullName, String> {

    @Override
    public boolean isValid(String fullNameField, ConstraintValidatorContext context) {
        if (fullNameField == null) {
            // can be null
            return true;
        }
        // 2 - 15 位字母 / 数字 / 简繁体字
        String FULL_NAME_REG_EXP = "(?!.*\\s$)((?=\\S)(?![0-9]+$)[\\u4E00-\\u9FA5A-Za-z0-9. ' ]{2,15})";
        return fullNameField.matches(FULL_NAME_REG_EXP);
    }
}
