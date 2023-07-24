package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // sucurity를 활성화하는 것.
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf();
        /*
        * 세션을 사용하지 않겠다는 선언.
        * 이유는 jwt를 사용하면 세션이 가진 보안 문제점을 해결할 수 있기 때문
        * */
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter)  // 모든 요청은 corsFilter를 타게 된다. crossOrigin 인증을 사용하지 않는다.
                .formLogin().disable()  // form 태그로 login을 만드는 것을 안한다는 의미
                .httpBasic().disable()  // 일반적인 http 로그인 방식(post)을 사용하지 않는다. 여기까지 기본 jwt 설정
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest()
                .permitAll();

        return http.build();
    }
}
