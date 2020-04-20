package github.javaguide.springsecurityjwtguide;

import github.javaguide.springsecurityjwtguide.system.entity.Role;
import github.javaguide.springsecurityjwtguide.system.enums.RoleType;
import github.javaguide.springsecurityjwtguide.system.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author shuang.kou
 */
@SpringBootApplication
public class SpringSecurityJwtGuideApplication implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    public static void main(java.lang.String[] args) {
        SpringApplication.run(SpringSecurityJwtGuideApplication.class, args);
    }

    @Override
    public void run(java.lang.String... args) {
        for (RoleType roleType : RoleType.values()){
            roleRepository.save(new Role(roleType.getName(), roleType.getDescription()));
        }
    }
}
