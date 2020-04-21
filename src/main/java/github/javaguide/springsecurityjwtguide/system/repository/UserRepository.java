package github.javaguide.springsecurityjwtguide.system.repository;

import github.javaguide.springsecurityjwtguide.system.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * @author shuang.kou
 */
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUserName(String username);

    @Transactional
    // TODO NOT WORK
    void deleteByUserName(String userName);
}
