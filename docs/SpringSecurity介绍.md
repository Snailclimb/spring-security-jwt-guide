## Spring Security 介绍

Spring Security 应该属于 Spring 全家桶中学习曲线比较陡峭的几个模块之一，下面我将从起源和定义这两个方面来简单介绍一下它。

- **起源：** Spring Security 实际上起源于 Acegi Security，这个框架能为基于 Spring 的企业应用提供强大而灵活安全访问控制解决方案，并且框架这个充分利用 Spring 的 IoC 和 AOP 功能，提供声明式安全访问控制的功能。后面，随着这个项目发展， Acegi Security 成为了Spring官方子项目，后来被命名为 “Spring Security”。
- **定义：**Spring Security 是一个功能强大且高度可以定制的框架，侧重于为Java 应用程序提供身份验证和授权。——[官方介绍](https://spring.io/projects/spring-security)。

## Session 和 Token 认证对比

### Session 认证图解

很多时候我们都是通过 SessionID 来实现特定的用户，SessionID 一般会选择存放在 Redis 中。举个例子：用户成功登陆系统，然后返回给客户端具有 SessionID 的 Cookie，当用户向后端发起请求的时候会把 SessionID 带上，这样后端就知道你的身份状态了。

关于这种认证方式更详细的过程如下：

![Session Based Authentication flow](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/Session-Based-Authentication-flow.png)

1. 用户向服务器发送用户名和密码用于登陆系统。
2. 服务器验证通过后，服务器为用户创建一个 Session，并将 Session信息存储 起来。
3. 服务器向用户返回一个 SessionID，写入用户的 Cookie。
4. 当用户保持登录状态时，Cookie 将与每个后续请求一起被发送出去。
5. 服务器可以将存储在 Cookie 上的 Session ID 与存储在内存中或者数据库中的 Session 信息进行比较，以验证用户的身份，返回给用户客户端响应信息的时候会附带用户当前的状态。

### Token 认证图解

在基于 Token 进行身份验证的的应用程序中，服务器通过`Payload`、`Header`和一个密钥(`secret`)创建令牌（`Token`）并将 `Token` 发送给客户端，客户端将 `Token` 保存在 Cookie 或者 localStorage 里面，以后客户端发出的所有请求都会携带这个令牌。你可以把它放在 Cookie 里面自动发送，但是这样不能跨域，所以更好的做法是放在 HTTP  Header 的 `Authorization`字段中：` Authorization: Bearer Token`。

关于这种认证方式更详细的过程如下：

![Token Based Authentication flow](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/Token-Based-Authentication.png)

1. 用户向服务器发送用户名和密码用于登陆系统。
2. 身份验证服务响应并返回了签名的 JWT，上面包含了用户是谁的内容。
3. 用户以后每次向后端发请求都在 Header 中带上 JWT。
4. 服务端检查 JWT 并从中获取用户相关信息。

## 项目涉及到的重要类说明

### 配置类

在本项目中我们自定义 `SecurityConfig` 继承了 `WebSecurityConfigurerAdapter`。 `WebSecurityConfigurerAdapter`提供`HttpSecurity`来配置 cors，csrf，会话管理和受保护资源的规则。

配置类中我们主要配置了：

1. 密码编码器 `BCryptPasswordEncoder`（存入数据库的密码需要被加密）。
2. 为` AuthenticationManager` 设置自定义的 `UserDetailsService`以及密码编码器；
3. 在 Spring Security 配置指定了哪些路径下的资源需要验证了的用户才能访问、哪些不需要以及哪些资源只能被特定角色访问；
4. 将我们自定义的两个过滤器添加到 Spring Security 配置中；
5. 将两个自定义处理权限认证方面的异常类添加到 Spring Security 配置中；

```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsServiceImpl userDetailsServiceImpl;

    /**
     * 密码编码器
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService createUserDetailsService() {
        return userDetailsServiceImpl;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 设置自定义的userDetailsService以及密码编码器
        auth.userDetailsService(userDetailsServiceImpl).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and()
                // 禁用 CSRF
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/auth/login").permitAll()
                // 指定路径下的资源需要验证了的用户才能访问
                .antMatchers("/api/**").authenticated()
                .antMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
                // 其他都放行了
                .anyRequest().permitAll()
                .and()
                //添加自定义Filter
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session（不创建会话）
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // 授权异常处理
                .exceptionHandling().authenticationEntryPoint(new JWTAuthenticationEntryPoint())
                .accessDeniedHandler(new JWTAccessDeniedHandler());

    }

}

```

**跨域：**

在这里踩的一个坑是:如果你没有设置`exposedHeaders("Authorization")`暴露 header 中的"Authorization"属性给客户端应用程序的话，前端是获取不到 token 信息的。

```java
@Configuration
public class CorsConfiguration implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                //暴露header中的其他属性给客户端应用程序
                //如果不设置这个属性前端无法通过response header获取到Authorization也就是token
                .exposedHeaders("Authorization")
                .allowCredentials(true)
                .allowedMethods("GET", "POST", "DELETE", "PUT")
                .maxAge(3600);
    }
}
```

### 工具类

```java
/**
 * @author shuang.kou
 */
public class JwtTokenUtils {


    /**
     * 生成足够的安全随机密钥，以适合符合规范的签名
     */
    private static byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
    private static SecretKey secretKey = Keys.hmacShaKeyFor(apiKeySecretBytes);

    public static String createToken(String username, List<String> roles, boolean isRememberMe) {
        long expiration = isRememberMe ? SecurityConstants.EXPIRATION_REMEMBER : SecurityConstants.EXPIRATION;

        String tokenPrefix = Jwts.builder()
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .claim(SecurityConstants.ROLE_CLAIMS, String.join(",", roles))
                .setIssuer("SnailClimb")
                .setIssuedAt(new Date())
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
        return SecurityConstants.TOKEN_PREFIX + tokenPrefix;
    }

    private boolean isTokenExpired(String token) {
        Date expiredDate = getTokenBody(token).getExpiration();
        return expiredDate.before(new Date());
    }

    public static String getUsernameByToken(String token) {
        return getTokenBody(token).getSubject();
    }

    /**
     * 获取用户所有角色
     */
    public static List<SimpleGrantedAuthority> getUserRolesByToken(String token) {
        String role = (String) getTokenBody(token)
                .get(SecurityConstants.ROLE_CLAIMS);
        return Arrays.stream(role.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private static Claims getTokenBody(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }
}
```



###  获取保存在服务端的用户信息类

Spring Security 提供的 `UserDetailsService`有一个通过名字返回 Spring Security 可用于身份验证的`UserDetails`对象的方法：`loadUserByUsername()`。

```java
package org.springframework.security.core.userdetails;
/**
 *加载用户特定数据的核心接口。
 */
public interface UserDetailsService {
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

`UserDetails`包含用于构建认证对象的必要信息（例如：用户名，密码）。

```java
package org.springframework.security.core.userdetails;
/**
 *提供用户核心信息的借口
 */
public interface UserDetails extends Serializable {
  Collection<? extends GrantedAuthority> getAuthorities();
  String getPassword();
  String getUsername();
  boolean isAccountNonExpired();
  boolean isAccountNonLocked();
  boolean isCredentialsNonExpired();
  boolean isEnabled();
}
```

一般情况下我们需要实现 `UserDetailsService` 借口并重写其中的 `loadUserByUsername()` 方法。

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserService userService;

    public UserDetailsServiceImpl(UserService userService) {
        this.userService = userService;
    }
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = userService.findUserByUserName(name);
        return new JwtUser(user);
    }

}
```

### 认证过滤器（重要）

> 建议看下面的过滤器介绍之前先了解一下过滤器的基础知识，以及如何在 Spring Boot 中实现过滤器。推荐阅读这篇文章：[SpringBoot 实现过滤器](https://github.com/Snailclimb/springboot-guide/blob/master/docs/basis/springboot-filter.md)

第一个过滤器主要`JWTAuthenticationFilter`用于根据用户的用户名和密码进行登录验证(用户请求中必须有用户名和密码这两个参数)，为此我们继承了 `UsernamePasswordAuthenticationFilter` 并且重写了下面三个方法：

1. `attemptAuthentication（）`: 验证用户身份。
2. `successfulAuthentication()` ： 用户身份验证成功后调用的方法。
3. `unsuccessfulAuthentication()`： 用户身份验证失败后调用的方法。

```java
/**
 * @author shuang.kou
 * 如果用户名和密码正确，那么过滤器将创建一个JWT Token 并在HTTP Response 的header中返回它，格式：token: "Bearer +具体token值"
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ThreadLocal<Boolean> rememberMe = new ThreadLocal<>();
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        // 设置登录请求的 URL
        super.setFilterProcessesUrl(SecurityConstants.AUTH_LOGIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            // 从输入流中获取到登录的信息
            LoginUser loginUser = objectMapper.readValue(request.getInputStream(), LoginUser.class);
            rememberMe.set(loginUser.getRememberMe());
            // 这部分和attemptAuthentication方法中的源码是一样的，
            // 只不过由于这个方法源码的是把用户名和密码这些参数的名字是死的，所以我们重写了一下
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    loginUser.getUsername(), loginUser.getPassword());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 如果验证成功，就生成token并返回
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) {

        JwtUser jwtUser = (JwtUser) authentication.getPrincipal();
        List<String> roles = jwtUser.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        // 创建 Token
        String token = JwtTokenUtils.createToken(jwtUser.getUsername(), roles, rememberMe.get());
        // Http Response Header 中返回 Token
        response.setHeader(SecurityConstants.TOKEN_HEADER, token);
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
    }
}
```

这个过滤器中有几个比较重要的地方说明：

1. `UsernamePasswordAuthenticationToken`:从登录请求中获取{用户名，密码}，`AuthenticationManager`将使用它来认证登录帐户。
2. `authenticationManager.authenticate(authRequest)`:这段代码主要对用户进行认证，当执行这段代码的时候会跳到`UserDetailsServiceImpl`中去调用`loadUserByUsername()`方法来验证（我们在配置类中配置了`AuthenticationManager`使用自定义的`UserDetailsServiceImpl`去验证用户信息）。当验证成功后会返回一个完整填充的`Authentication`对象(包括授予的权限)，然后会去调用`successfulAuthentication`方法。

```java
package org.springframework.security.authentication;
 /**
  *尝试验证Authentication对象，如果成功，将返回一个完整填充的Authentication对象(包括授予的权限)。
  */
public interface AuthenticationManager {
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;
}
```

### 授权过滤器（重要）

这个过滤器继承了 `BasicAuthenticationFilter`，主要用于处理身份认证后才能访问的资源，它会检查 HTTP 请求是否存在带有正确令牌的 Authorization 标头并验证 token 的有效性。

当用户使用 token 对需要权限才能访问的资源进行访问的时候，这个类是主要用到的，下面按照步骤来说一说每一步到底都做了什么。

1. 当用户使用系统返回的 token 信息进行登录的时候 ，会首先经过`doFilterInternal（）`方法，这个方法会从请求的Header中取出 token 信息，然后判断 token 信息是否为空以及 token 信息格式是否正确。
2. 如果请求头中有token 并且 token 的格式正确，则进行解析并判断 token 的有效性，然后会在 Spring  Security 全局设置授权信息`SecurityContextHolder.getContext().setAuthentication(getAuthentication(authorization));`

```java
/**
 * 过滤器处理所有HTTP请求，并检查是否存在带有正确令牌的Authorization标头。例如，如果令牌未过期或签名密钥正确。
 *
 * @author shuang.kou
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private static final Logger logger = Logger.getLogger(JWTAuthorizationFilter.class.getName());

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String authorization = request.getHeader(SecurityConstants.TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if (authorization == null || !authorization.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置授权信息
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(authorization));
        super.doFilterInternal(request, response, chain);
    }

    /**
     * 这里从token中获取用户信息并新建一个token
     */
    private UsernamePasswordAuthenticationToken getAuthentication(String authorization) {
        String token = authorization.replace(SecurityConstants.TOKEN_PREFIX, "");

        try {
            String username = JwtTokenUtils.getUsernameByToken(token);
            // 通过 token 获取用户具有的角色
            List<SimpleGrantedAuthority> userRolesByToken = JwtTokenUtils.getUserRolesByToken(token);
            if (!StringUtils.isEmpty(username)) {
                return new UsernamePasswordAuthenticationToken(username, null, userRolesByToken);
            }
        } catch (SignatureException | ExpiredJwtException exception) {
            logger.warning("Request to parse JWT with invalid signature . Detail : " + exception.getMessage());
        }
        return null;
    }
}
```

### 获取当前用户

我们在讲过滤器的时候说过，当认证成功的用户访问系统的时候，它的认证信息会被设置在 Spring  Security 全局中。那么，既然这样，我们在其他地方获取到当前登录用户的授权信息也就很简单了，通过`SecurityContextHolder.getContext().getAuthentication();`方法即可。

`SecurityContextHolder` 保存 `SecurityContext` 的信息，`SecurityContext `保存已通过认证的 `Authentication` 认证信息。

为此，我们实现了一个专门用来获取当前用户的类：

```java
/**
 * @author shuang.kou
 * 获取当前请求的用户
 */
@Component
public class CurrentUser {

    private final UserDetailsServiceImpl userDetailsService;

    public CurrentUser(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public JwtUser getCurrentUser() {
        return (JwtUser) userDetailsService.loadUserByUsername(getCurrentUserName());
    }

    /**
     * TODO:由于在JWTAuthorizationFilter这个类注入UserDetailsServiceImpl一致失败，
     * 导致无法正确查找到用户，所以存入Authentication的Principal为从 token 中取出的当前用户的姓名
     */
    private static String getCurrentUserName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() != null) {
            return (String) authentication.getPrincipal();
        }
        return null;
    }
}
```

### 异常相关

#### AccessDeniedHandler

`JWTAccessDeniedHandler`实现了`AccessDeniedHandler`主要用来解决认证过的用户访问需要权限才能访问的资源时的异常。

```java
/**
 * @author shuang.kou
 * AccessDeineHandler 用来解决认证过的用户访问需要权限才能访问的资源时的异常
 */
public class JWTAccessDeniedHandler implements AccessDeniedHandler {
    /**
     * 当用户尝试访问需要权限才能的REST资源而权限不足的时候，
     * 将调用此方法发送401响应以及错误信息
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        accessDeniedException = new AccessDeniedException("Sorry you don not enough permissions to access it!");
        response.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
    }
}

```

#### AuthenticationEntryPoint

`JWTAuthenticationEntryPoint` 实现了 `AuthenticationEntryPoint` 用来解决匿名用户访问需要权限才能访问的资源时的异常

```java
/**
 * @author shuang.kou
 * AuthenticationEntryPoint 用来解决匿名用户访问需要权限才能访问的资源时的异常
 */
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
    /**
     * 当用户尝试访问需要权限才能的REST资源而不提供Token或者Token过期时，
     * 将调用此方法发送401响应以及错误信息
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
    }
}
```

### 验证权限配置的 Controller

这个是 `UserControler` 主要用来检测权限配置是否生效。

`getAllUser（）`方法被注解` @PreAuthorize("hasAnyRole('ROLE_DEV','ROLE_PM')")`修饰代表这个方法可以被DEV，PM 这两个角色访问，而`deleteUserById()` 被注解` @PreAuthorize("hasAnyRole('ROLE_ADMIN')")`修饰代表只能被 ADMIN 访问。

```java
/**
 * @author shuang.kou
 */
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    private final CurrentUser currentUser;

    public UserController(UserService userService, CurrentUser currentUser) {
        this.userService = userService;
        this.currentUser = currentUser;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ROLE_DEV','ROLE_PM')")
    public ResponseEntity<Page<User>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum, @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        System.out.println("当前访问该接口的用户为：" + currentUser.getCurrentUser().toString());
        Page<User> allUser = userService.getAllUser(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }


    @DeleteMapping("/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<User> deleteUserById(@RequestParam("username") String username) {
        userService.deleteUserByUserName(username);
        return ResponseEntity.ok().build();
    }
}
```

## 推荐阅读

- [Spring Security 中文文档](https://www.docs4dev.com/docs/zh/spring-security/5.1.2.RELEASE/reference)
- [【老徐】Spring Security(一) —— Architecture Overview](https://www.cnkirito.moe/spring-security-1/)