package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

/*
* 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 이 필터가 있음.
* 이 필터가 동작할 때는 /login을 요청해서 username과 password를 POST 메소드로 전송할 때 작동함.
* jwt에서 formLogin을 막았기 때문에 내가 직접 securityFilter에 등록시켜야 함
* */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    /*
    * /login 요청을 하면 로그인 시도를 위해서 실행하는 함수 
    * 
    * */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAutenticationFilter 로그인 시도 중");

        /*
        * 1. /login post 요청이 오면 username과 password를 securityConfig의 authenticationManager가 물고 와서 로그인 시도를 함
        * 2. 로그인 시도를 하면 principalDetailsService가 실행이 되고
        * 3. loadUserByUsername 메소드 실행이 되서 userDetails 객체를 PrincipalDetails로 리턴해서 세션에 담아줌.
        *    굳이 세션에 담아주는 이유는 세션에 안담으면 권한관리가 안되기 때문.
        * 4. jwt 토큰을 만들어서 응답해주면 됨.
        * */

        // request에 있는 username과 password를 파싱해서 자바 object로 받기
        //objectManager 객체는 json 데이터를 파싱할 수 있다
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            // dto 필드 값에 request에 있는 username과 password의 값을 넣음.
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // username으로 토큰을 만들어 준다.
        // formLogin을 하면 알아서 다 만들어 주지만 jwt는 내가 만들어야 됨.
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword());

        // principalDetailsService에 loadUserByUsername 함수가 실행되면서 토큰에 있는 username만 가져감.
        // password는 spring이 알아서 처리해줌.
        // 토큰을 통해서 로그인 시도를 해보고 정상이면 authentication이 리턴 됨.
        // DB에 있는 username과 password가 일치함.
        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);
        /*
         * authentication 에는 userDetails 타입만 들어감.
         * userDetails 타입이 PrincipalDetails 이고
         * authentication이 userDetails의 부모 클래스이다 보니 다운캐스팅을 해야 함.
         *
         * sout이 제대로 나온다는건 DB에 있는 username과 password가 일치해서 로그인 성공했다는 것.
         * */
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("이게 뜨면 로그인 된거임. => "+principalDetails.getMember().getUsername());
        System.out.println("loginDto-> "+loginRequestDto);


        /*
        * 이제 이 authentication 객체를 session에 저장해야 하는데 방법이 authentication을 리턴하면 된다.
        * 근데 jwt를 쓰면 session을 쓰지 않는데 session에 저장하는 이유는
        * 권한 관리를 할 수 있기 때문.
        * */
        return authentication;
    }

    /*
    * attemptAuthentication 실행 후 인증이 정상적으로 되면 successfulAuthentication가 실행됨.
    * 여기서 jwt 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response로 보내주면 됨.
    * */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("이거 나오면 attemptAuthentication 잘 되서 로그인 된거임. ");
        /*
        * 이 정보를 통해서 jwt 토큰을 생성함.
        * */
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername()) // 토큰이름
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))     // 토큰 만료시간 현재시간으로부터 10분
                .withClaim("id", principalDetails.getMember().getId())        // 비공개 클레임, 내가 넣고 싶은 값.
                .withClaim("username", principalDetails.getMember().getUsername()) // 비공개 클레임, 내가 넣고 싶은 값.
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // 서버만 알고 있는 시크릿 키값.
        //  Bearer하고 한칸 꼭 띄우기
        //  Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJI어쩌구가 토큰값. postman에서 확인가능
        /*
         이제 요청할 때마다 이 jwt 토큰을 가지고 요청을 해야함.
         서버는 jwt 토큰이 유효한지 판단을 해야 하는 데 이를 위해 필터를 만들어야 함.
        * */
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
