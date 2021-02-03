package github.javaguide.springsecurityjwtguide.system.web.controller;

import github.javaguide.springsecurityjwtguide.BaseTest;
import github.javaguide.springsecurityjwtguide.system.web.request.UserRegisterRequest;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserControllerTest extends BaseTest {
    @Test
    public void should_sign_up_success() throws Exception {
        UserRegisterRequest userRegisterRequest = new UserRegisterRequest("yasuo111", "123456", "shuangkou");
        this.mockMvc.perform(post("/users/sign-up")
                .content(objectMapper.writeValueAsString(userRegisterRequest))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    public void should_sign_up_fail_and_get_400_code_when_full_name_is_not_valid() throws Exception {
        UserRegisterRequest invalidFullNameUserRegisterRequest = new UserRegisterRequest("yasuo111", "123456", "11111");
        this.mockMvc.perform(post("/users/sign-up")
                .content(objectMapper.writeValueAsString(invalidFullNameUserRegisterRequest))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$.code").value(1003))
                .andExpect(MockMvcResultMatchers.jsonPath("$.message").value("方法参数验证失败"));
    }

    @Test
    public void should_get_all_user_fail_when_not_login() throws Exception {
        this.mockMvc.perform(get("/users")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }
}