package github.javaguide.springsecurityjwtguide.system.repository;

import github.javaguide.springsecurityjwtguide.system.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author shuang.kou
 */
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);
}
