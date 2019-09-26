# spring-security-jwt-guide

ENGLISH

**如果国内访问缓慢的话，可以通过码云查看：** https://gitee.com/SnailClimb/spring-security-jwt-guide 。

## 下载配置

1. git clone https://github.com/Snailclimb/spring-security-jwt-guide.git
2. 打开项目并且等待Maven下载好相关依赖。建议使用idea 打开，并确保你的idea 下载了 lombok插件。
3. 修改 `application.properties` 将数据库连接信息改成你自己的。
## 示例

### 1.注册一个账号

![Register](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/1-register.png)

### 2.登录

![Login](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/2-login.png)

### 3.使用正确Token访问需要进行身份验证的资源

![Access resources that require authentication](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/3-visit-authenticated-resourse-have-token.png)

### 4.不带Token访问需要进行身份验证的资源

![Access resources that require authentication  without token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/4-visit-authenticated-resourse-not-have-token.png)

### 5.使用不正确Token访问需要进行身份验证的资源

![Access resources that require authentication  with not correct token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/5-visit-authenticated-resourse-not-have-valid-token.png)

## 参考

- https://dev.to/keysh/spring-security-with-jwt-3j76
