package github.javaguide.springsecurityjwtguide.system.entity;

import github.javaguide.springsecurityjwtguide.system.enums.UserStatus;
import lombok.Data;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author shuang.kou
 */
@Entity
@Data
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "status")
    @Enumerated(value = EnumType.STRING)
    private UserStatus status;

    @Column(name = "role")
    private String roles;

    public List<SimpleGrantedAuthority> getRoles() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        Arrays.stream(roles.split(",")).forEach(role ->
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        return authorities;
    }

}
