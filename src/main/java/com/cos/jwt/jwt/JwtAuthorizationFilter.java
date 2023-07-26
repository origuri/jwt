package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.Entity.Member;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.repository.MemberRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소가 요청됨.");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader -> "+jwtHeader);

        /*
        * header가 있는지 확인함.
        * 만약 jwtHeader가 null이거나 Bearer로 시작하지 않으면
        * 그냥 접속 거부되고 끝
        * */
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }

        // jwt 토큰 검증해서 정상적인 사용자인지 확인.
        // 앞에 Bearer하고 띄어쓰기 한 칸 값을 없애서 순수 토큰만 남김.
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        /*
        * jwt에 들어있는 username을 가져오는 과정.
        * 시크릿 키값을 입력해서 빌드하고, jwt 토큰으로 서명하고, 거기서 username을 가져와서 String 타입으로 캐스팅한다.
        * */
        String username =
                JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 이루어졌다면 username이 비어있지 않을 것.
        if(username != null){
            System.out.println("서명 잘 됫음. username-> "+username);
            // 찾아지면 정상적인 사용자
            Member member = memberRepository.findByUsername(username);

            /*
            * 로그인할 때 만드는 객체 말고 요청이 들어왓을 때
            * authentication 객체를 강제로 만들어준다.
            * jwt에서 서명이 제대로 이루어졌고, 그로 인해 username이 있는 거니까 로그인 했다는 것을 검증한 것.
            * 그러므로 비밀번호쪽 파라미터는 null로 넣어도 상관 없음.
            * 그리고 권한을 가져옴.
            * */
            PrincipalDetails principalDetails = new PrincipalDetails(member);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            System.out.println("jwt 토큰 서명으로 만든 권한 -> "+authentication);

            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
