## 前言

[Spring Security](https://spring.io/projects/spring-security) 是 Spring 全家桶中非常强大的一个用来做身份验证以及权限控制的框架，我们可以轻松地扩展它来满足我们当前系统安全性这方面的需求。

但是 Spring Security 相比于其他一些技术比如 JPA 来说更难上手，很多人初学的时候很难通过看视频或者文档发就很快能独立写一个 Demo 出来，于是后面可能就放弃了学习这个东西。

刚来公司的时候的入职培训实战项目以及现在正在做的项目都用到了 Spring Security 这个强大的安全验证框架，可以看出这个框架在身份验证以及权限验证领域可以说应该是比较不错的选择。由于之前经历项目的这部分模块都不是自己做的，所以对于 Spring Security 并不是太熟悉。于是自/己抽时间对这部分知识学习了一下，并实现了一个简单的 Demo 。这个 Demo 主要用到了 **Spring Security** 和 **Spring Boot** 这两门技术，并且所有的依赖采用的都是最新的稳定版本。初次之外，这个项目还用到了 JPA 这门技术。

由于自己的能力以及时间有限，所以一定还有很多可以优化的地方，有兴趣的朋友可以一起完善，期待你的 PR。

## 项目介绍

Spring Security JWT Guide 是一个基于 Spring Boot 和 Spring Security 的认证授权示例项目，展示了如何使用 JWT (JSON Web Token) 实现现代化的无状态认证系统。项目采用了 Java 21 和 Spring Boot 3.5.0，结合 Redis 实现了完整的用户认证、授权和会话管理功能。

**后端技术栈如下**：

- 核心框架：Spring Boot 3.5.0
- 安全框架：Spring Security 6.5.0
- ORM 框架：JPA
- 数据库：H2 内存数据库（示例）
- 缓存：Redis
- JWT 实现：JJWT

**你能从这个项目中学习到什么？**

1. Spring Security +JWT 实现登入登出以及权限校验
2. JPA 实现审计功能、多对多的映射关系如何通过关联表实现

## 代办

- [x] 将 SpringBoot 升级版 3.x，JDK 升级为 21。
- [x] 增加 H2 内存数据库支持，无须 MySQL，一键启动项目启动后访问 [http://localhost:9333/api/h2-console](http://localhost:9333/api/h2-console) (用户名:root,密码:123456)
- [x] 异常处理部分代码重构，优化返回结构
- [x] 新建一个 role 表，然后通过新建一个 role_user 表的形式，将用户与角色关联起来
- [x] 文件结构重构
- [x] 增加 jpa 审计功能
- [x] 登出功能：redis 保存 token 信息（key->user id,value->token），登出后将 redis 中的 token 信息删除
- [x] 重新登录将上一次登录生成的 token 弄失效（解决未过期的 token 还是可以用的问题）：重新登录会将 redis 中保存的 token 信息进行更新

## 如何运行项目

1. git clone https://github.com/Snailclimb/spring-security-jwt-guide.git
2. 打开项目并且等待 Maven 下载好相关依赖。建议使用 Intellij IDEA 打开，并确保你的 Intellij IDEA 下载了 lombok 插件。
3. 下载 redis 并`application.yaml`中 redis 的配置
4. 运行项目（相关数据表会被自动创建，不了解的看一下 JPA）

## 测试

### 注册

**URL:**

`POST http://localhost:9333/api/users/sign-up`

**RequestBody:**

```json
{"userName":"123456","fullName":"shuangkou","password":"123456"}
```

![注册](./pictures/sign-up.png)

新注册的用户默认绑定的角色为：用户（USER）和管理者（MANAGER）。

### 登录

**URL:**

`POST http://localhost:9333/api/auth/login`

**RequestBody:**

```json
{"username": "123456", "password": "123456","rememberMe":true}
```

![登录](./pictures/login.png)

### 登出

**URL:**

`POST http://localhost:9333/api/auth/logout`

![](pictures/logout.png)

### 使用正确 Token 访问需要进行身份验证的资源

我们使用 GET 请求访问 `/api/users`，这个接口的访问权限是

```java
@PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MANAGER','ROLE_ADMIN')")
```

![Access resources that require authentication](./pictures/access-resources-that-require-authentication.png)

### 不带 Token 或者使用无效 Token 访问

我们使用 GET 请求访问 `/api/users`，但是不带 token 或者带上无效 token。

![Access resources that require authentication without token or with invalid token](./pictures/access-resources-that-require-authentication2.png)

### 带了正确 Token 但是访问权限不够

我们使用 DELETE 请求访问 `/api/users?username=xxx`，携带有效的 token ，但是 token 的访问权限不够。

![](./pictures/not-have-enough-permission.png)
