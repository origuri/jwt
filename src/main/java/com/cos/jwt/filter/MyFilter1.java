package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyFilter1/* implements Filter*/ {
   /* @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터1");

        *//*
        * 강제 형변환을 함으로써 httpServlet에 있는 메소드도 사용할 수 잇음.
        * ex) getHeader 메소드는 http에만 있음. servlet에는 없음.
        * *//*
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        System.out.println(req.getMethod());
        *//*
        * id와 pw가 정상적으로 들어와서 로그인이 완료 되면 ori 토큰을 만들어주고 응답해준다.
        * 다시 클라이언트에서 요청이 워면 header에 ori 토큰을 들고 올것임.
        * 이 때 이 ori 토큰이 내가 만든 토큰인지만 확인해주면 됨(RSA< HS256)
        *
        * *//*
        if(req.getMethod().equals("POST")){
            System.out.println("post요청됨.");
            String headAuth = req.getHeader("Authorization");
            System.out.println("headAuth -> "+headAuth);
            if(headAuth.equals("ori")){
                *//*
                 * 필터 체인을 다시 타기 위해서 등록을 해줌.
                 * *//*
                chain.doFilter(req, res);
            } else {
                System.out.println("권한없음");
            }
        }


    }*/
}
