package github.javaguide.springsecurityjwtguide.security.config;

import github.javaguide.springsecurityjwtguide.security.common.constants.SecurityConstants;
import github.javaguide.springsecurityjwtguide.security.exception.JwtAccessDeniedHandler;
import github.javaguide.springsecurityjwtguide.security.exception.JwtAuthenticationEntryPoint;
import github.javaguide.springsecurityjwtguide.security.filter.JwtAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static java.util.Collections.singletonList;

/**
 * @author shuang.kou Saving
 * @version 1.1
 * @date 2020.11.28 14:16
 * @description Spring Security配置类
 **/
@EnableWebSecurity
@Configuration
public class SecurityConfiguration {

    private final StringRedisTemplate stringRedisTemplate;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfiguration(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.jwtAuthenticationEntryPoint = new JwtAuthenticationEntryPoint();
        this.jwtAccessDeniedHandler = new JwtAccessDeniedHandler();
    }

    /**
     * 密码编码器
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 禁用 CSRF
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                    // 指定的接口直接放行
                    .requestMatchers(SecurityConstants.H2_CONSOLE).permitAll()
                    .requestMatchers(HttpMethod.POST, SecurityConstants.SYSTEM_WHITELIST).permitAll()
                    // 其他的接口都需要认证后才能请求
                    .anyRequest().authenticated()
                )
                //添加自定义Filter
                .addFilterBefore(new JwtAuthorizationFilter(authenticationManager, stringRedisTemplate), UsernamePasswordAuthenticationFilter.class)
                // 不需要session（不创建会话）
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 授权异常处理
                .exceptionHandling(exceptionHandling -> exceptionHandling
                    .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                    .accessDeniedHandler(jwtAccessDeniedHandler)
                );
        // 防止H2 web 页面的Frame 被拦截
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        return http.build();
    }

    /**
     * Cors配置优化
     **/
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(singletonList("*"));
        // configuration.setAllowedOriginPatterns(singletonList("*"));
        configuration.setAllowedHeaders(singletonList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT", "OPTIONS"));
        configuration.setExposedHeaders(singletonList(SecurityConstants.TOKEN_HEADER));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
