package com.cos.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터1");
        /*
        * 필터 체인을 다시 타기 위해서 등록을 해줌.
        * */
        chain.doFilter(request, response);
    }
}
