# spring-security-jwt-guide

**如果国内访问缓慢的话，可以通过码云查看：** https://gitee.com/SnailClimb/spring-security-jwt-guide 。

## Setup

1. git clone https://github.com/Snailclimb/spring-security-jwt-guide.git
2. 打开项目并且等待Maven下载好相关依赖。建议使用idea 打开，并确保你的idea 下载了 lombok插件。
3. 修改 `application.properties` 将数据库连接信息改成你自己的。
3. change `application.properties` change the database connection information parameter to your own
## Example

### 1.Register an account

![Register](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/1-register.png)

### 2.Login

![Login](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/2-login.png)

### 3.Access resources that require authentication  with the correct token

![Access resources that require authentication](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/3-visit-authenticated-resourse-have-token.png)

### 4.Access resources that require authentication  without token

![Access resources that require authentication  without token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/4-visit-authenticated-resourse-not-have-token.png)

### 5.Access resources that require authentication  with not correct token

![Access resources that require authentication  with not correct token](https://my-blog-to-use.oss-cn-beijing.aliyuncs.com/2019-7/5-visit-authenticated-resourse-not-have-valid-token.png)



## Reference

- https://dev.to/keysh/spring-security-with-jwt-3j76
