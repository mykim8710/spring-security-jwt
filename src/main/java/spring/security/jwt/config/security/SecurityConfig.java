package spring.security.jwt.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import spring.security.jwt.config.security.jwt.JwtAuthenticationFilter;
import spring.security.jwt.config.security.jwt.JwtAuthorizationFilter;
import spring.security.jwt.config.security.jwt.JwtProvider;
import spring.security.jwt.repository.UserRepository;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 활성화 => 기본 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true) // secure annotation 활성화
public class SecurityConfig {
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    private final CorsConfig corsConfig;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;


    // 인증을 무시할 경로들을 설정 >> static resource 보안설정
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers("/css/**", "/js/**");
    }

    @Bean
    public SecurityFilterChain filterChainSession(HttpSecurity httpSecurity) throws Exception {
        // csrf token disable, use jwt token
        httpSecurity
                .csrf()
                .disable();

        // add filter
        httpSecurity
                .addFilter(corsConfig.corsFilter())     // 모든 요청은 이 필터를 탄다 : cors정책에서 벗어나라
                .addFilter(jwtAuthenticationFilter())   // extends UsernamePasswordAuthenticationFilter
                .addFilter(jwtAuthorizationFilter());   // extends BasicAuthenticationFilter < OncePerRequestFilter


        httpSecurity
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session not used
                .and()
                .formLogin().disable()  // form tag login not used
                .httpBasic().disable();
                // Basic : headers(Authorization, id or pw)
                // Bearer : id, pw로 token(jwt token)을 생성, 이 token을 들고 요청하는 방식(노출이 되더라도 id, pw보다는 안전)
                // token => 유효시간이 있음


        httpSecurity
                .exceptionHandling()
                .accessDeniedHandler(customAccessDeniedHandler)            // 권한실패
                .authenticationEntryPoint(customAuthenticationEntryPoint); // jwt token 인증실패


        httpSecurity
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/home").authenticated()
                .anyRequest().permitAll();

        return httpSecurity.build();
    }

    // user password encoder 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager 빈 등록
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * [POST] /sign-in 으로 요청 시 작동하는 필터 extends UsernamePasswordAuthenticationFilter
     * UsernamePasswordAuthenticationFilter는 httpSecurity.formLogin(), [POST] /login [username, password]일때 작동
     * 현재는 jwt방식을 사용하기 때문에 formLogin().disable() => UsernamePasswordAuthenticationFilter는 동작하지않음
     * UsernamePasswordAuthenticationFilter 상속받아 jwt 사용 시 로그인 용 필터를 구현 => security 에 등록하여 작동
     *
     * 로그인(인증, 신원확인)을 요청하는 사용자의 정보로 UsernamePasswordAuthenticationToken 발급
     *
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();

        filter.setAuthenticationManager(authenticationManager());  // set authenticationManager
        filter.setFilterProcessesUrl("/sign-in");                  // set login url(filter가 작동할 url)
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler); // set AuthenticationSuccessHandler(인증 성공 핸들러)
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler); // set AuthenticationFailureHandler(인증 실패 핸들러)
        filter.afterPropertiesSet();

        return filter;
    }

    /**
     * JwtAuthorizationFilter extends BasicAuthenticationFilter
     * 인증이나 권한이 필요한 url요청 시 이 필터를 타게됨
     * => jwt 토큰 검증이 필요한 api, url 요청 시 작동
     * => jwt 토큰 검증이 필요없는 api, url 설정가능
     */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() throws Exception {
        return new JwtAuthorizationFilter(authenticationManager(), userRepository, jwtProvider);
    }
}



