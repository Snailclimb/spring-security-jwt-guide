# spring-security-jwt-guide

[English version](https://github.com/Snailclimb/spring-security-jwt-guide/blob/master/README-ENGLISH.md)

**如果国内访问缓慢的话，可以通过码云查看：** https://gitee.com/SnailClimb/spring-security-jwt-guide 。

## 介绍

[Spring Security](https://spring.io/projects/spring-security ) 是 Spring 全家桶中非常强大的一个用来做身份验证以及权限控制的框架，我们可以轻松地扩展它来满足我们当前系统安全性这方面的需求。

但是 Spring Security 相比于其他一些技术比如 JPA 来说更难上手，很多人初学的时候很难通过看视频或者文档发就很快能独立写一个 Demo 出来，于是后面可能就放弃了学习这个东西。

刚来公司的时候的入职培训实战项目以及现在正在做的项目都用到了 Spring Security 这个强大的安全验证框架，可以看出这个框架在身份验证以及权限验证领域可以说应该是比较不错的选择。由于之前经历项目的这部分模块都不是自己做的，所以对于 Spring Security 并不是太熟悉。于是自/己抽时间对这部分知识学习了一下，并实现了一个简单的 Demo 。这个 Demo 主要用到了 **Spring Security** 和 **Spring Boot** 这两门技术，并且所有的依赖采用的都是最新的稳定版本。初次之外，这个项目还用到了 JPA 这门技术。项目代码结构如下(chrome 插件：Octoree)，整体还是比较清晰的，由于自己的能力以及时间有限，所以一定还有很多可以优化的地方，有兴趣的朋友可以一起完善，期待你的 PR。

![代码结构](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/代码结构.png)

## 下载配置

1. git clone https://github.com/Snailclimb/spring-security-jwt-guide.git
2. 打开项目并且等待 Maven 下载好相关依赖。建议使用 Intellij IDEA 打开，并确保你的 Intellij IDEA 下载了 lombok 插件。
3. 修改 `application.properties` 将数据库连接信息改成你自己的。
4. 运行项目（相关数据表会被自动创建，不了解的看一下 JPA）

## 示例

### 1.注册一个账号

![Register](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/1-register.png)

### 2.登录

![Login](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/2-login.png)

### 3.使用正确 Token 访问需要进行身份验证的资源

![Access resources that require authentication](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/3-visit-authenticated-resourse-have-token.png)

### 4.不带 Token 访问需要进行身份验证的资源

![Access resources that require authentication  without token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/4-visit-authenticated-resourse-not-have-token.png)

### 5.使用不正确 Token 访问需要进行身份验证的资源

![Access resources that require authentication  with not correct token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/5-visit-authenticated-resourse-not-have-valid-token.png)

## 参考

- https://dev.to/keysh/spring-security-with-jwt-3j76
