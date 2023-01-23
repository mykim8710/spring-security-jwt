package spring.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import spring.security.jwt.config.auth.PrincipalDetail;
import spring.security.jwt.domain.User;
import spring.security.jwt.repository.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * spring secutity가 필터를 가지고 있는데 그 필터 중, BasicAuthenticationFilter라는 것이 있음.
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때, 위 필터를 무조건 타게되어있음.
 * 만약, 권한, 인증이 필요한 주소가 아니라면 이 필터를 타지 않음
 */

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    /**
     * 인증이나 권한이 필요한 url요청 시 이 필터를 타게됨
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // jwt 토큰을 검증해서 정상적이 사용자인지 확인
        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            log.error("header is null or jwtHeader is invalid.");
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");
        log.info("jwt Token = {}", token);

        // 토큰 검증
        Integer userId = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET_KEY))
                            .build()
                            .verify(token)
                            .getClaim("id").asInt();

        log.info("userId = {}", userId);

        if(userId != null) {
            User user = userRepository.findById(Long.valueOf(userId)).orElseThrow(() -> new UsernameNotFoundException("없는 사용자입니다."));

            PrincipalDetail principalDetail = new PrincipalDetail(user);

            // jwt 토큰 서명을 통해서 서명이 정상이면 Authentication객체를 생성
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetail, null, principalDetail.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 값 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
