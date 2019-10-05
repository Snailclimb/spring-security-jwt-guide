package github.javaguide.springsecurityjwtguide.system.repository;

import github.javaguide.springsecurityjwtguide.system.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * @author shuang.kou
 */
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);

//    @Query("select status from user where username= :username")
//    Optional<String> findUserStatusByName(@Param("username") String username);
}
