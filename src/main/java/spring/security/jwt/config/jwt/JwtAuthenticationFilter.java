package spring.security.jwt.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.security.jwt.config.auth.PrincipalDetail;
import spring.security.jwt.dto.RequestUserSignInDto;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티의 UsernamePasswordAuthenticationFilter가 있음
 * /login 요청해서 username, password를 post 전송하면 UsernamePasswordAuthenticationFilter 동작
 */

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    //  /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("/login 요청됨, JwtAuthenticationFilter 실행");

        // 1. username, password 받아서
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            RequestUserSignInDto signInDto = objectMapper.readValue(request.getInputStream(), RequestUserSignInDto.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                                                            signInDto.getUsername(),
                                                                            signInDto.getPassword());
            System.out.println("authenticationToken = " + authenticationToken);

            // 2. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService, loadUserByUsername()가 호출됨
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetail principalDetail = (PrincipalDetail) authentication.getPrincipal();
            System.out.println("Authentication : "+principalDetail.getUser().getUsername()); // 로그인 성공

            // 3. PrincipalDetails를 세션에 담고 : 권한관리를 위함
            // 4. jwt 토큰을 만들어서 응답해주면 됨


            return authentication;

        }catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication()실행후 인증이 정상적으로 되었다면 successfulAuthentication()가 실행됨
    // 여기서 jwt 토큰을 발급하고 요청한 사용자에게 jwt토큰을 response해주면됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("인증정상, successfulAuthentication() 실행");

        PrincipalDetail principalDetail = (PrincipalDetail) authResult.getPrincipal();

        String jwtToken = JWT.create()
                                .withSubject(principalDetail.getUsername()) // payload - subject : 토큰 제목
                                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                                .withClaim("id", principalDetail.getUser().getId())
                                .withClaim("username", principalDetail.getUser().getUsername()) // 비공개클래임
                                .sign(Algorithm.HMAC512(JwtProperties.SECRET_KEY));

        log.info("jwtToken : {}", jwtToken);
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX +jwtToken);
    }
}
