package github.javaguide.springsecurityjwtguide.security.controller;

import github.javaguide.springsecurityjwtguide.system.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;


/**
 * @author shuang.kou
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity registerUser(@RequestBody Map<String, String> registerUser) {
        userService.saveUser(registerUser);
        return ResponseEntity.ok().build();
    }
}
