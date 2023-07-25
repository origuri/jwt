package com.cos.jwt.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*
* 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 이 필터가 있음.
* 이 필터가 동작할 때는 /login을 요청해서 username과 password를 POST 메소드로 전송할 때 작동함.
* jwt에서 formLogin을 막았기 때문에 내가 직접 securityFilter에 등록시켜야 함
* */
@RequiredArgsConstructor
public class JwtAutenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    /*
    * /login 요청을 하면 로그인 시도를 위해서 실행하는 함수 
    * 
    * */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAutenticationFilter 로그인 시도 중");

        /*
        * 1. /login post 요청이 오면 username과 password를 받아서 authenticationManager가 로그인 시도를 함
        * 2. 로그인 시도를 하면 principalDetailsService가 실행이 되고
        * 3. loadUserByUsername 메소드 실행이 되서 userDetails 객체를 PrincipalDetails로 리턴해서 세션에 담아줌.
        *    굳이 세션에 담아주는 이유는 세션에 안담으면 권한관리가 안되기 때문.
        * 4. jwt 토큰을 만들어서 응답해주면 됨.
        * */
        return super.attemptAuthentication(request, response);
    }
}
