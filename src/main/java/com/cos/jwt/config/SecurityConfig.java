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
                /*
                * http는 header에 Authorization이라는 키 값에 id와 pw를 담아서 인증을 받는 방식
                * 하지만 id와 pw가 암호화가 안되다 보니 정보 노출의 가능성이 있음.
                * 그래서 https가 나왔고 s는 secure의 약자, 여기서는 암호화가 됨.
                * 이러한 방식들을 httpBasic 방식이라고 함.
                *
                * bearer 방식은 header에 id와 pw가 아닌 token을 가져가기 때문에 basic보다 안전함.
                * token은 유효시간이 있어서 일정 시간 이후에는 사용이 불가하므로 조금 더 안전.
                * 이 토큰이 jwt
                * */
                .httpBasic().disable()
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
