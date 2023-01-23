package spring.security.jwt.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.filter.CorsFilter;
import spring.security.jwt.config.jwt.JwtAuthenticationFilter;
import spring.security.jwt.config.jwt.JwtAuthorizationFilter;
import spring.security.jwt.repository.UserRepository;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 활성화 => 기본 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true) // secure annotation 활성화
public class SecurityConfig {
    private final CorsFilter corsFilter;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;


    // user password encoder 빈등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 인증을 무시할 경로들을 설정 >> static resource 보안설정
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers("/css/**", "/js/**");
    }

    @Bean
    public SecurityFilterChain filterChainSession(HttpSecurity httpSecurity) throws Exception {
        //httpSecurity.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);

        // csrf token disable, use jwt token
        httpSecurity
                .csrf()
                .disable();


        httpSecurity
                .addFilter(corsFilter) // 모든 요청은 이 필터를 탄다 : cors정책에서 벗어나라
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), objectMapper))  // AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository));


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
                .accessDeniedHandler(accessDeniedHandler())
        //        .authenticationEntryPoint(authenticationEntryPoint()) //filter단에서 exception
        ;

        httpSecurity
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint("/");
    }

}



