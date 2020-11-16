package github.javaguide.springsecurityjwtguide.security.service;

import github.javaguide.springsecurityjwtguide.security.dto.LoginRequest;
import github.javaguide.springsecurityjwtguide.security.entity.JwtUser;
import github.javaguide.springsecurityjwtguide.security.common.utils.JwtTokenUtils;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author shuang.kou
 * @createTime 2020年11月16日 16:06:00
 **/
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthService {
    private final UserService userService;

    public String getToken(LoginRequest loginRequest) {
        User user = userService.find(loginRequest.getUsername());
        if (!userService.check(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("The user name or password is not correct.");
        }
        JwtUser jwtUser = new JwtUser(user);
        if (!jwtUser.isEnabled()) {
            throw new BadCredentialsException("User is forbidden to log in");
        }
        List<String> authorities = jwtUser.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return JwtTokenUtils.createToken(user.getUserName(), authorities, loginRequest.getRememberMe());
    }
}
