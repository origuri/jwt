package com.cos.jwt.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.cos.jwt.Entity.Member;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.repository.MemberRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

/*
 * 시큐리티가 filter를 가지고 있는데 그 중 BasicAutenticationFitler 라는 것이 있다.
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때 BasicAutenticationFitler 필터를 무조건 타게 되어있음.
 * 만약 권한이나 인증이 필요한 주소가 아니라면 BasicAutenticationFitler 필터를 타지 않는다.
 * */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private MemberRepository memberRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
    }
    /*
     * 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터가 작동됨.
     * */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        /*
        * 여기서 응답을 한번 하고 chain.doFitler로 응답을 한번 더 하니까 에러가 발생함.
        * 지워줘야 함.
        * super.doFilterInternal(request,response,chain);
        * */
        System.out.println("인증이나 권한이 필요한 주소가 요청됨.");

        String header = request.getHeader(JwtProperties.HEADER_STRING);

        /*
         * header가 있는지 확인함.
         * 만약 jwtHeader가 null이거나 Bearer로 시작하지 않으면
         * 그냥 접속 거부되고 끝
         * */
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        System.out.println("header : " + header);

        // jwt 토큰 검증해서 정상적인 사용자인지 확인.
        // 앞에 Bearer하고 띄어쓰기 한 칸 값을 없애서 순수 토큰만 남김
        String token = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        // 토큰 검증 (이게 인증이기 때문에 AuthenticationManager도 필요 없음)
        // 내가 SecurityContext에 집적접근해서 세션을 만들때 자동으로 UserDetailsService에 있는
        // loadByUsername이 호출됨.
        /*
         * jwt에 들어있는 username을 가져오는 과정.
         * 시크릿 키값을 입력해서 빌드하고, jwt 토큰으로 서명하고, 거기서 username을 가져와서 String 타입으로 캐스팅한다.
         * */
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
                .getClaim("username").asString();

        // 서명이 정상적으로 이루어졌다면 username이 비어있지 않을 것.
        if (username != null) {
            System.out.println("서명 잘 됫음. username-> "+username);

            // 찾아지면 정상적인 사용자
            Member member = memberRepository.findByUsername(username);

            // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
            // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
            /*
             * 로그인할 때 만드는 객체 말고 요청이 들어왓을 때
             * authentication 객체를 강제로 만들어준다.
             * jwt에서 서명이 제대로 이루어졌고, 그로 인해 username이 있는 거니까 로그인 했다는 것을 검증한 것.
             * 그러므로 비밀번호쪽 파라미터는 null로 넣어도 상관 없음.
             * 그리고 권한을 가져옴.
             * */
            PrincipalDetails principalDetails = new PrincipalDetails(member);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                    null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                    principalDetails.getAuthorities());
            System.out.println("jwt 토큰 서명으로 만든 권한 -> "+authentication);

            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

}