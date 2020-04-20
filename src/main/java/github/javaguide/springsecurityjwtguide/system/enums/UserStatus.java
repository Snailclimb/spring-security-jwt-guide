package github.javaguide.springsecurityjwtguide.system.enums;

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * @author shuang.kou
 */

public enum UserStatus {
    CAN_USE("can use in system"),
    CAN_NOT_USE("can not use in system");

    private String status;

    UserStatus(String status) {
        this.status = status;
    }

    public String getName() {
        return this.status;
    }

}
