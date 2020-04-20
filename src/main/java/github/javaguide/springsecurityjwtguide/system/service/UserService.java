package github.javaguide.springsecurityjwtguide.system.service;

import github.javaguide.springsecurityjwtguide.system.entity.Role;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.entity.UserRole;
import github.javaguide.springsecurityjwtguide.system.enums.RoleType;
import github.javaguide.springsecurityjwtguide.system.enums.UserStatus;
import github.javaguide.springsecurityjwtguide.system.exception.UserNameAlreadyExistException;
import github.javaguide.springsecurityjwtguide.system.repository.RoleRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * @author shuang.kou
 */
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void saveUser(Map<String, String> registerUser) {
        Optional<User> optionalUser = userRepository.findByUsername(registerUser.get("username"));
        if (optionalUser.isPresent()) {
            throw new UserNameAlreadyExistException("User name already exist!Please choose another user name.");
        }
        User user = new User();
        user.setUsername(registerUser.get("username"));
        user.setPassword(bCryptPasswordEncoder.encode(registerUser.get("password")));
        Optional<Role> roleRepositoryByName = roleRepository.findByName(RoleType.STUDENT);
        user.setStatus(UserStatus.CAN_USE);
        userRepository.save(user);
        if (roleRepositoryByName.isPresent()){
            UserRole userRole= new UserRole(user,roleRepositoryByName.get());
            userRoleRepository.save(userRole);
        }else {
            Role studentRole = roleRepository.save(new Role(RoleType.STUDENT, "学生"));
            userRoleRepository.save(new UserRole(user,studentRole));
        }
    }

    public User findUserByUserName(String name) {
        return userRepository.findByUsername(name)
                .orElseThrow(() -> new UsernameNotFoundException("No user found with username " + name));
    }

    public void deleteUserByUserName(String name) {
        userRepository.deleteByUsername(name);
    }


    public Page<User> getAllUser(int pageNum, int pageSize) {
        return userRepository.findAll(PageRequest.of(pageNum, pageSize));
    }
}
