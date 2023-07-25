package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        // 모든 url에 대해 필터를 건다.
        bean.addUrlPatterns("/*");
        // 우선 순위를 정할 수 있는데 숫자가 낮을수록 우선순위를 갖는다.
        // 하지만 securityFilter가 가장 우선순위를 갖는다 .
        // securityFilter보다 빨리 실행하게 싶으면 securityConfig에 addBeforeFilter메소드 사용해야한다.
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        // 모든 url에 대해 필터를 건다.
        bean.addUrlPatterns("/*");
        // 우선 순위를 정할 수 있는데 숫자가 낮을수록 우선순위를 갖는다.
        bean.setOrder(1);
        return bean;
    }
}
