package github.javaguide.springsecurityjwtguide.security.filter;

import github.javaguide.springsecurityjwtguide.security.constants.SecurityConstants;
import github.javaguide.springsecurityjwtguide.security.service.UserDetailsServiceImpl;
import github.javaguide.springsecurityjwtguide.security.utils.JwtTokenUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * @author shuang.kou
 * @description 过滤器处理所有HTTP请求，并检查是否存在带有正确令牌的Authorization标头。例如，如果令牌未过期或签名密钥正确。
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserDetailsServiceImpl userDetailsService;
    private static final Logger logger = Logger.getLogger(JwtAuthorizationFilter.class.getName());

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserDetailsServiceImpl userDetailsService) {
        super(authenticationManager);
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        if (token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            SecurityContextHolder.clearContext();
        } else {
            UsernamePasswordAuthenticationToken authentication = getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

    /**
     * 获取用户认证信息 Authentication
     */
    private UsernamePasswordAuthenticationToken getAuthentication(String authorization) {
        log.info("get authentication");
        String token = authorization.replace(SecurityConstants.TOKEN_PREFIX, "");
        try {
            String username = JwtTokenUtils.getUsernameByToken(token);
            logger.info("checking username:" + username);
            if (!StringUtils.isEmpty(username)) {
                // 这里我们是又从数据库拿了一遍,避免用户的角色信息有变
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
                return userDetails.isEnabled() ? usernamePasswordAuthenticationToken : null;
            }
        } catch (SignatureException | ExpiredJwtException | MalformedJwtException | IllegalArgumentException exception) {
            logger.warning("Request to parse JWT with invalid signature . Detail : " + exception.getMessage());
        }
        return null;
    }
}
