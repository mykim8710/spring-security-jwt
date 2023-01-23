package spring.security.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import spring.security.jwt.filter.MyFilter1;

@Configuration
public class FilterConfig {

//    @Bean
//    public FilterRegistrationBean<MyFilter1> myFilter1(){
//        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
//        bean.addUrlPatterns("/*");
//        bean.setOrder(0);// 낮은 번호가 필터 중 가장 먼저 실행
//        return bean;
//    }

}
