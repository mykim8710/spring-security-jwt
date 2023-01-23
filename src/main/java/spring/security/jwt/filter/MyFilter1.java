package spring.security.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("My Filter 1");
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        req.setCharacterEncoding("UTF-8");
        res.setCharacterEncoding("UTF-8");


        // 토큰 : 만들어줘야함,
        // id, pw 정상적으로 등러와서 로그인이 완료되면 토큰을 만들어주고 이것을 응답
        // 요청할때마다 header의 Authorization애 value값으로 토큰을 가지고오고
        // 가져온 토큰이 유효한 토큰인지 검증(내가 발행한 토큰인지)

        String method = req.getMethod();
        if(method.equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            if(headerAuth.equals("token")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.write("auth fail");
            }
        }
    }
}
