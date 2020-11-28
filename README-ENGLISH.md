# spring-security-jwt-guide

## Introduce

[Spring Security](https://spring.io/projects/spring-security )  is a very powerful framework in the Spring family for authentication and permission control, and we can easily extend it to meet our current system security requirements.

However, compared with some other technologies such as JPA, Spring Security is more difficult to get started. Many people can hardly write a Demo independently after reading video or sending documents, so they may give up learning this thing later.

Spring Security, a powerful Security authentication framework, has been used in the induction training practical project when I first came to the company and the projects I am working on now. It can be seen that this framework is a good choice in the field of authentication and permission authentication. I am not familiar with Spring Security because I did not make this part of the module of the previous project by myself. So I took the time to learn this part of knowledge and implemented a simple Demo. This Demo mainly USES **Spring Security** and **Spring Boot**, and all the dependencies adopt the latest stable version. Beyond the initial project, the JPA technology was also used. The code structure of the project is as follows (chrome plug-in: octree), which is relatively clear as a whole. Due to my limited ability and time, there must be a lot of areas that can be optimized. Interested friends can improve it together.

## Setup

1. git clone https://github.com/Snailclimb/spring-security-jwt-guide.git
2. open project and wait maven to install project Dependencies
3. change `application.properties` change the database connection information parameter to your own
4. Run the project (related data tables will be created automatically, if you don't understand, take a look at JPA)

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