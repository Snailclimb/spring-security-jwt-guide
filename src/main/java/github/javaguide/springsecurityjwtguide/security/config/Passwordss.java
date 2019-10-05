package github.javaguide.springsecurityjwtguide.security.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Passwordss {
    public static void main(String[] args) {
        PasswordEncoder encoder = new BCryptPasswordEncoder();

        for (int i = 0; i < 3; i++) {
            String password = encoder.encode("123456");

            // passwd - password from database
            System.out.println(password); // print hash

            // true for all 5 iteration
            System.out.println(encoder.matches("123456", password));
        }
    }
}
