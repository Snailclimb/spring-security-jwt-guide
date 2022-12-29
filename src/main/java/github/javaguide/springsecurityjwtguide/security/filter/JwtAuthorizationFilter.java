package github.javaguide.springsecurityjwtguide.security.filter;

import github.javaguide.springsecurityjwtguide.security.common.constants.SecurityConstants;
import github.javaguide.springsecurityjwtguide.security.common.utils.JwtTokenUtils;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author shuang.kou
 * @description 过滤器处理所有HTTP请求，并检查是否存在带有正确令牌的Authorization标头。例如，如果令牌未过期或签名密钥正确。
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final StringRedisTemplate stringRedisTemplate;

    private final Map<String, String> cacheMap;

    private Boolean redisCacheSwitch;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  StringRedisTemplate stringRedisTemplate,
                                  Map<String, String> cacheMap,
                                  Boolean redisCacheSwitch) {
        super(authenticationManager);
        this.stringRedisTemplate = stringRedisTemplate;
        this.cacheMap = cacheMap;
        this.redisCacheSwitch = redisCacheSwitch;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        if (token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
            return;
        }
        String tokenValue = token.replace(SecurityConstants.TOKEN_PREFIX, "");
        UsernamePasswordAuthenticationToken authentication = null;
        try {
            String previousToken = "";
            if (redisCacheSwitch) {
                previousToken = stringRedisTemplate.opsForValue().get(JwtTokenUtils.getId(tokenValue));
            }else {
                previousToken = cacheMap.get(JwtTokenUtils.getId(tokenValue));
            }

            if (!token.equals(previousToken)) {
                SecurityContextHolder.clearContext();
                chain.doFilter(request, response);
                return;
            }
            authentication = JwtTokenUtils.getAuthentication(tokenValue);
        } catch (JwtException e) {
            logger.error("Invalid jwt : " + e.getMessage());
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }
}


