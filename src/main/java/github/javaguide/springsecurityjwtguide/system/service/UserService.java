package github.javaguide.springsecurityjwtguide.system.service;

import com.google.common.collect.ImmutableMap;
import github.javaguide.springsecurityjwtguide.system.dto.UserRegisterRequest;
import github.javaguide.springsecurityjwtguide.system.entity.Role;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.entity.UserRole;
import github.javaguide.springsecurityjwtguide.system.enums.RoleType;
import github.javaguide.springsecurityjwtguide.system.exception.UserNameAlreadyExistException;
import github.javaguide.springsecurityjwtguide.system.exception.NotFoundException;
import github.javaguide.springsecurityjwtguide.system.repository.RoleRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

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

    public void saveUser(UserRegisterRequest userRegisterRequest) {
        User user = getUser(userRegisterRequest);
        userRepository.save(user);
        /**
         * 给用户绑定两个角色：用户和管理者
         */
        String userRoleName = RoleType.USER.getName();
        Role studentRole = roleRepository.findByName(userRoleName).orElseThrow(() -> new NotFoundException(ImmutableMap.of("roleName", userRoleName)));
        String managerName = RoleType.MANAGER.getName();
        Role managerRole = roleRepository.findByName(managerName).orElseThrow(() -> new NotFoundException(ImmutableMap.of("roleName", userRoleName)));
        userRoleRepository.save(new UserRole(user, studentRole));
        userRoleRepository.save(new UserRole(user, managerRole));
    }

    private User getUser(UserRegisterRequest userRegisterRequest) {
        java.lang.String fullName = userRegisterRequest.getFullName();
        java.lang.String userName = userRegisterRequest.getUserName();
        java.lang.String password = userRegisterRequest.getPassword();
        checkUserNameNotExist(userName);
        return User.builder().fullName(fullName)
                .username(userName)
                .password(bCryptPasswordEncoder.encode(password)).build();
    }

    private void checkUserNameNotExist(java.lang.String userName) {
        Optional<User> optionalUser = userRepository.findByUsername(userName);
        if (optionalUser.isPresent()) {
            throw new UserNameAlreadyExistException(ImmutableMap.of("username", userName));
        }
    }

    public User findUserByUserName(java.lang.String name) {
        return userRepository.findByUsername(name).orElseThrow(() -> new NotFoundException(ImmutableMap.of("username", name)));
    }

    public void deleteUserByUserName(java.lang.String name) {
        userRepository.deleteByUsername(name);
    }


    public Page<User> getAllUser(int pageNum, int pageSize) {
        return userRepository.findAll(PageRequest.of(pageNum, pageSize));
    }
}
