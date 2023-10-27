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
2. 在 Spring Security 配置指定了哪些路径下的资源需要验证了的用户才能访问、哪些不需要以及哪些资源只能被特定角色访问；
3. 将我们自定义的过滤器添加到 Spring Security 配置中；
4. 将两个自定义处理权限认证方面的异常类添加到 Spring Security 配置中；
5. 对跨域请求`Cors`的配置优化（在这里踩的一个坑是：如果你没有设置`exposedHeaders("Authorization")`暴露 header 中的"Authorization"属性给客户端应用程序的话，前端是获取不到 token 信息的。）

```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final StringRedisTemplate stringRedisTemplate;

    public SecurityConfiguration(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    /**
     * 密码编码器
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors(withDefaults())
                // 禁用 CSRF
                .csrf().disable()
                .authorizeRequests()
                // 指定的接口直接放行
                // swagger
                .antMatchers(SecurityConstants.SWAGGER_WHITELIST).permitAll()
                .antMatchers(SecurityConstants.H2_CONSOLE).permitAll()
                .antMatchers(HttpMethod.POST, SecurityConstants.SYSTEM_WHITELIST).permitAll()
                // 其他的接口都需要认证后才能请求
                .anyRequest().authenticated()
                .and()
                //添加自定义Filter
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), stringRedisTemplate))
                // 不需要session（不创建会话）
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // 授权异常处理
                .exceptionHandling().authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .accessDeniedHandler(new JwtAccessDeniedHandler());
        // 防止H2 web 页面的Frame 被拦截
        http.headers().frameOptions().disable();
    }

    /**
     * Cors配置优化
     **/
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(singletonList("*"));
        // configuration.setAllowedOriginPatterns(singletonList("*"));
        configuration.setAllowedHeaders(singletonList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT", "OPTIONS"));
        //暴露header中的其他属性给客户端应用程序
        //如果不设置这个属性前端无法通过response header获取到Authorization也就是token
        configuration.setExposedHeaders(singletonList(SecurityConstants.TOKEN_HEADER));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}

```

### 工具类

```java
/**
 * @author shuang.kou
 * @description JWT工具类
 */
public class JwtTokenUtils {


    /**
     * 生成足够的安全随机密钥，以适合符合规范的签名
     */
    private static final byte[] API_KEY_SECRET_BYTES = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(API_KEY_SECRET_BYTES);

    public static String createToken(String username, String id, List<String> roles, boolean isRememberMe) {
        long expiration = isRememberMe ? SecurityConstants.EXPIRATION_REMEMBER : SecurityConstants.EXPIRATION;
        final Date createdDate = new Date();
        final Date expirationDate = new Date(createdDate.getTime() + expiration * 1000);
        String tokenPrefix = Jwts.builder()
                .setHeaderParam("type", SecurityConstants.TOKEN_TYPE)
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .claim(SecurityConstants.ROLE_CLAIMS, String.join(",", roles))
                .setId(id)
                .setIssuer("SnailClimb")
                .setIssuedAt(createdDate)
                .setSubject(username)
                .setExpiration(expirationDate)
                .compact();
        return SecurityConstants.TOKEN_PREFIX + tokenPrefix; // 添加 token 前缀 "Bearer ";
    }

    public static String getId(String token) {
        Claims claims = getClaims(token);
        return claims.getId();
    }

    public static UsernamePasswordAuthenticationToken getAuthentication(String token) {
        Claims claims = getClaims(token);
        List<SimpleGrantedAuthority> authorities = getAuthorities(claims);
        String userName = claims.getSubject();
        return new UsernamePasswordAuthenticationToken(userName, token, authorities);
    }

    /**
     * 获取用户所有角色
     */
    private static List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        String role = (String) claims.get(SecurityConstants.ROLE_CLAIMS);
        return Arrays.stream(role.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private static Claims getClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

}
```

### 授权过滤器（重要）

> 建议看下面的过滤器介绍之前先了解一下过滤器的基础知识，以及如何在 Spring Boot 中实现过滤器。推荐阅读这篇文章：[SpringBoot 实现过滤器](https://github.com/Snailclimb/springboot-guide/blob/master/docs/basis/springboot-filter.md)

这个过滤器继承了 `BasicAuthenticationFilter`，主要用于处理身份认证后才能访问的资源，它会检查 HTTP 请求是否存在带有正确令牌的 Authorization 标头并验证 token 的有效性。

当用户使用 token 对需要权限才能访问的资源进行访问的时候，这个类是主要用到的，下面按照步骤来说一说每一步到底都做了什么。

1. 当用户使用系统返回的 token 信息进行登录的时候 ，会首先经过`doFilterInternal（）`方法，这个方法会从请求的Header中取出 token 信息，然后判断 token 信息是否为空以及 token 信息格式是否正确。
2. 如果请求头中有token 并且 token 的格式正确，则进行解析并判断 token 的有效性，然后会在 Spring  Security 全局设置授权信息`SecurityContextHolder.getContext().setAuthentication(authorization);`

```java
/**
 * @author shuang.kou
 * @description 过滤器处理所有HTTP请求，并检查是否存在带有正确令牌的Authorization标头。例如，如果令牌未过期或签名密钥正确。
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final StringRedisTemplate stringRedisTemplate;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, StringRedisTemplate stringRedisTemplate) {
        super(authenticationManager);
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if (token == null || !token.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            SecurityContextHolder.clearContext();
            chain.doFilter(request, response);
            return;
        }
        // 如果请求头中有token，则进行解析
        String tokenValue = token.replace(SecurityConstants.TOKEN_PREFIX, "");
        UsernamePasswordAuthenticationToken authentication = null;
        try {
            String previousToken = stringRedisTemplate.opsForValue().get(JwtTokenUtils.getId(tokenValue));
            // 如果请求头中的token与redis中存储的之前的token不同则直接放行
            if (!token.equals(previousToken)) {
                SecurityContextHolder.clearContext();
                chain.doFilter(request, response);
                return;
            }
            // 设置授权信息
            authentication = JwtTokenUtils.getAuthentication(tokenValue);
        } catch (JwtException e) {
            logger.error("Invalid jwt : " + e.getMessage());
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
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
 * @description 获取当前请求的用户
 */
@Component
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CurrentUserUtils {

    private final UserService userService;

    public User getCurrentUser() {
        return userService.find(getCurrentUserName());
    }

    private  String getCurrentUserName() {
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
 * @description AccessDeineHandler 用来解决认证过的用户访问无权限资源时的异常
 */
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    /**
     * 当用户尝试访问需要权限才能的REST资源而权限不足的时候，
     * 将调用此方法发送403响应以及错误信息
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
 * @description AuthenticationEntryPoint 用来解决匿名用户访问需要权限才能访问的资源时的异常
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    /**
     * 当用户尝试访问需要权限才能的REST资源而不提供Token或者Token错误或者过期时，
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

`getAllUser（）`方法被注解` @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")`修饰代表这个方法可以被USER，MANAGER，ADMIN 这三个角色访问，而`deleteUserByUserName()` 被注解` @PreAuthorize("hasAnyRole('ROLE_ADMIN')")`修饰代表只能被 ADMIN 访问。

```java
/**
 * @author shuang.kou
 */
@RestController
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@RequestMapping("/users")
@Api(tags = "用户")
public class UserController {

    private final UserService userService;

    @PostMapping("/sign-up")
    @ApiOperation("用户注册")
    public ResponseEntity<Void> signUp(@RequestBody @Valid UserRegisterRequest userRegisterRequest) {
        userService.save(userRegisterRequest);
        return ResponseEntity.ok().build();
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")
    @ApiOperation("获取所有用户的信息（分页）")
    public ResponseEntity<Page<UserRepresentation>> getAllUser(@RequestParam(value = "pageNum", defaultValue = "0") int pageNum, @RequestParam(value = "pageSize", defaultValue = "10") int pageSize) {
        Page<UserRepresentation> allUser = userService.getAll(pageNum, pageSize);
        return ResponseEntity.ok().body(allUser);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @ApiOperation("更新用户")
    public ResponseEntity<Void> update(@RequestBody @Valid UserUpdateRequest userUpdateRequest) {
        userService.update(userUpdateRequest);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @ApiOperation("根据用户名删除用户")
    public ResponseEntity<Void> deleteUserByUserName(@RequestParam("username") String username) {
        userService.delete(username);
        return ResponseEntity.ok().build();
    }
}
```

## 推荐阅读

- [Spring Security 中文文档](https://www.docs4dev.com/docs/zh/spring-security/5.1.2.RELEASE/reference)
- [【老徐】Spring Security(一) —— Architecture Overview](https://www.cnkirito.moe/spring-security-1/)
