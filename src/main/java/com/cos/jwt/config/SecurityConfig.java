package com.cos.jwt.config;


import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.jwt.JwtAuthenticationFilter;
import com.cos.jwt.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.MemberRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;



@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private CorsConfig corsConfig;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                /*
                 * http.addFilter(new MyFilter1());
                 * 이렇게 걸면 에러가 발생함. securityfilter만 넣을 수 잇는데 일반 filter 타입이기 때문임
                 * 해결책으로 http.addFilterBefore() 메소드를 사용하는 것.
                 *
                 * http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);
                 * BasicAuthenticationFilter.class가 securityFilter임.
                 * BasicAuthenticationFilter.class가 발동하기 전에 내가 만든 일반 MyFilter가 실행되도록 함.
                 * 하지만 일반 filter를 굳이 securityConfig에서 걸 필요는 없다.
                 *
                 * FilterConfig 클래스를 하나 만들어서 컨트롤한다.
                 * 이렇게 만든 필터는 securityFilter가 동작이 완료된 후에 실행이 된다.
                 * 하지만 securityFilter보다 빠르게 발동하게 하려면
                 * http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);
                 * 로 걸어주면 된다.
                 * SecurityContextPersistenceFilter.class가 securityFilter중 가장 먼저 실행되기 때문.
                 * */
                .csrf().disable()
                /*
                 * 세션을 사용하지 않겠다는 선언.
                 * 이유는 jwt를 사용하면 세션이 가진 보안 문제점을 해결할 수 있기 때문
                 * */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable() // form 태그로 login을 만드는 것을 안한다는 의미
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
                .apply(new MyCustomDsl()) // 커스텀 필터 등록, jwt,corsFilter
                .and()
                .authorizeRequests(authroize -> authroize.antMatchers("/api/v1/user/**")
                        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/manager/**")
                        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .antMatchers("/api/v1/admin/**")
                        .access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll())
                .build();
    }
    /*
    * securityFilter 말고 내가 만든 filter를 등록해 놓는 클래스
    * */
    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // 로그인 관련 필터를 사용하기 위한 authenticationManager 객체
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter()) // 모든 요청은 corsFilter를 타게 된다. crossOrigin 인증을 사용하지 않는다.
                    // formLogin을 막았기 때문에 새로 만든 loginSecurity
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, memberRepository));

        }
    }

}