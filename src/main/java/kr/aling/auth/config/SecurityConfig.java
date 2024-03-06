package kr.aling.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 설정 class.
 *
 * @author 이수정
 * @since 1.0
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /**
     * SecurityFilterChain 설정 Bean.
     *
     * @param http http 요청에 대한 웹 기반 보안 구성 객체
     * @return 설정한 SecurityFilterChain Bean
     * @throws Exception HttpSecurity 발생 예외
     * @author 이수정
     * @since 1.0
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll();

        return http.build();
    }

    /**
     * PasswordEncoder 설정 Bean.
     *
     * @return BCryptPasswordEncoder
     * @author 이수정
     * @since 1.0
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
