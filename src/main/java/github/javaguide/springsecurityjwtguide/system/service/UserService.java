package github.javaguide.springsecurityjwtguide.system.service;

import com.google.common.collect.ImmutableMap;
import github.javaguide.springsecurityjwtguide.system.web.representation.UserRepresentation;
import github.javaguide.springsecurityjwtguide.system.web.request.UserRegisterRequest;
import github.javaguide.springsecurityjwtguide.system.entity.Role;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.entity.UserRole;
import github.javaguide.springsecurityjwtguide.system.enums.RoleType;
import github.javaguide.springsecurityjwtguide.system.exception.ResourceNotFoundException;
import github.javaguide.springsecurityjwtguide.system.exception.UserNameAlreadyExistException;
import github.javaguide.springsecurityjwtguide.system.repository.RoleRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRepository;
import github.javaguide.springsecurityjwtguide.system.repository.UserRoleRepository;
import github.javaguide.springsecurityjwtguide.system.web.request.UserUpdateRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

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

    public void save(UserRegisterRequest userRegisterRequest) {
        checkUserNameNotExist(userRegisterRequest.getUserName());
        User user = User.of(userRegisterRequest);
        user.setPassword(bCryptPasswordEncoder.encode(userRegisterRequest.getPassword()));
        userRepository.save(user);
        //给用户绑定两个角色：用户和管理者
        Role studentRole = roleRepository.findByName(RoleType.USER.getName()).orElseThrow(() -> new ResourceNotFoundException(ImmutableMap.of("roleName", RoleType.USER.getName())));
        Role managerRole = roleRepository.findByName(RoleType.MANAGER.getName()).orElseThrow(() -> new ResourceNotFoundException(ImmutableMap.of("roleName", RoleType.MANAGER.getName())));
        userRoleRepository.save(new UserRole(user, studentRole));
        userRoleRepository.save(new UserRole(user, managerRole));
    }

    public User find(String userName) {
        return userRepository.findByUserName(userName).orElseThrow(() -> new ResourceNotFoundException(ImmutableMap.of("username", userName)));
    }

    public void update(UserUpdateRequest userUpdateRequest) {
        User user = userRepository.findByUserName(userUpdateRequest.getUserName()).orElseThrow(() -> new ResourceNotFoundException(ImmutableMap.of("username", userUpdateRequest.getUserName())));
        user.updateFrom(userUpdateRequest);
        userRepository.save(user);
    }


    public void delete(String userName) {
        userRepository.deleteByUserName(userName);
    }

    public Page<UserRepresentation> getAll(int pageNum, int pageSize) {
        return userRepository.findAll(PageRequest.of(pageNum, pageSize)).map(User::toUserRepresentation);
    }

    private void checkUserNameNotExist(String userName) {
        boolean exist = userRepository.findByUserName(userName).isPresent();
        if (exist) {
            throw new UserNameAlreadyExistException(ImmutableMap.of("username", userName));
        }
    }
}
