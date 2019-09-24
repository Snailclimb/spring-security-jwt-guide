package github.javaguide.springsecurityjwtguide.system.controller;

import github.javaguide.springsecurityjwtguide.system.entity.User;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author shuang.kou
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public ResponseEntity<Page<User>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum, @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        Page<User> allUser = userService.getAllUser(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }

    @DeleteMapping("/user/{id}")
    public ResponseEntity<User> getAllUser(@PathVariable("id") Integer id) {

        return ResponseEntity.ok().build();
    }
}
