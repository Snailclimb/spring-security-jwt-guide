package github.javaguide.springsecurityjwtguide.security.utils;

import github.javaguide.springsecurityjwtguide.security.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author shuang.kou
 */
public class JwtTokenUtils {

    /**
     * 角色的key
     **/
    private static final String ROLE_CLAIMS = "rol";
    /**
     * 过期时间是3600秒，既是1个小时
     */
    private static final long EXPIRATION = 60L;
    /**
     * 选择了记住我之后的过期时间为7天
     */
    private static final long EXPIRATION_REMEMBER = 604800L;

    /**
     *    生成足够的安全随机密钥，以适合符合规范的签名
     */
    private static byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
    private static SecretKey secretKey = Keys.hmacShaKeyFor(apiKeySecretBytes);

    public static String createToken(String username, List<String> roles, boolean isRememberMe) {
        long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;

        String tokenPrefix = Jwts.builder()
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .claim(ROLE_CLAIMS, String.join(",", roles))
                .setIssuer("SnailClimb")
                .setIssuedAt(new Date())
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
        return SecurityConstants.TOKEN_PREFIX + tokenPrefix;
    }

    public static String getUsernameByToken(String token) {
        return getTokenBody(token).getSubject();
    }

    /**
     * 获取用户所有角色
     */
    public static List<SimpleGrantedAuthority> getUserRolesByToken(String token) {
        String role = (String) getTokenBody(token)
                .get(ROLE_CLAIMS);
        return Arrays.stream(role.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Token是否过期
     */
    public static boolean isExpiration(String token) {
        return getTokenBody(token).getExpiration().before(new Date());
    }

    private static Claims getTokenBody(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }
}
