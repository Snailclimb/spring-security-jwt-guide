package github.javaguide.springsecurityjwtguide.system.web.controller;

import github.javaguide.springsecurityjwtguide.security.utils.CurrentUserUtils;
import github.javaguide.springsecurityjwtguide.system.service.UserService;
import github.javaguide.springsecurityjwtguide.system.web.representation.UserRepresentation;
import github.javaguide.springsecurityjwtguide.system.web.request.UserRegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

/**
 * @author shuang.kou
 */
@RestController
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final CurrentUserUtils currentUserUtils;

    @PostMapping("/sign-up")
    public ResponseEntity signUp(@RequestBody @Valid UserRegisterRequest userRegisterRequest) {
        userService.save(userRegisterRequest);
        return ResponseEntity.ok().build();
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")
    public ResponseEntity<Page<UserRepresentation>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum, @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        System.out.println("当前访问该接口的用户为：" + currentUserUtils.getCurrentUser().getUserName());
        Page<UserRepresentation> allUser = userService.getAll(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }

    @DeleteMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity deleteUserByUserName(@RequestParam("username") String username) {
        userService.delete(username);
        return ResponseEntity.ok().build();
    }
}
