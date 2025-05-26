package github.javaguide.springsecurityjwtguide.system.entity;


import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;

/**
 * @author shuang.kou
 */
@Data
@NoArgsConstructor
@Entity
@Table(name = "role")
public class Role extends AbstractAuditBase {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<UserRole> userRoles = new ArrayList<>();

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }
}
