package github.javaguide.springsecurityjwtguide.security.controller;

import github.javaguide.springsecurityjwtguide.BaseTest;
import github.javaguide.springsecurityjwtguide.security.dto.LoginRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class AuthControllerTest extends BaseTest {
    @Test
    public void should_login_success_and_get_token_in_header() throws Exception {
        LoginRequest loginRequest = new LoginRequest("root", "root", true);
        this.mockMvc.perform(post("/auth/login")
                .content(objectMapper.writeValueAsString(loginRequest))
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

}