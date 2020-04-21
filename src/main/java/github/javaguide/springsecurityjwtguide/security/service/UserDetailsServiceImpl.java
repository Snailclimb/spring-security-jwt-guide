package github.javaguide.springsecurityjwtguide.security.service;

import github.javaguide.springsecurityjwtguide.security.entity.JwtUser;
import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * @author shuang.kou
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService userService;

    public UserDetailsServiceImpl(UserService userService) {
        this.userService = userService;
    }
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = userService.find(name);
        return new JwtUser(user);
    }

}
