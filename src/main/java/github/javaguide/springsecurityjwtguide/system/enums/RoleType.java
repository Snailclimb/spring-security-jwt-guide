package github.javaguide.springsecurityjwtguide.system.enums;

import lombok.Getter;

/**
 * @author shuang.kou
 */

@Getter
public enum RoleType {
    USER("USER", "用户"),
    TEMP_USER("TEMP_USER", "临时用户"),
    MANAGER("MANAGER", "管理者"),
    ADMIN("ADMIN", "Admin");
    String name;
    String description;

    RoleType(java.lang.String name, java.lang.String description) {
        this.name = name;
        this.description = description;
    }
}
