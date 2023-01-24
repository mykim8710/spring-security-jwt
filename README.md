# Spring Security + JWT init

## [Project Info]
- Springboot 2.7.8, Java 11
- Name(project name) : spring-security-jwt
- Language : Java
- Type : Gradle(Groovy)
- Packaging : Jar
- [Project Metadata]
  - Group: spring.security
  - Artifact: jwt
  - Package name: spring.security.jwt
- [Dependencies]
  - Spring Web
  - Spring Security
  - Spring Data JPA
  - Lombok
  - H2 Database
  - thymeleaf
  - jwts

## [Project package design]
```
└── src
    ├── main
    │   ├── java
    │   │     └── spring.security.init
    │   │            ├── SpringSecurityJwtApplication(C)
    │   │            ├── api
    │   │            │    └── UserApiController(C)
    │   │            ├── dto
    │   │            │    └── RequestUserSignDto(C)
    │   │            ├── entity
    │   │            │    └── User(C)
    │   │            ├── global
    │   │            │    ├── init
    │   │            │    │    └── InitUserInsert(C)
    │   │            │    └── result
    │   │            │         │── error
    │   │            │         │     │── BusinessException(C)
    │   │            │         │     │── ErrorCode(E)
    │   │            │         │     └── GlobalExceptionHandler(C)
    │   │            │         │── SuccessCode(E)
    │   │            │         └── CommonResult(C)
    │   │            │── config
    │   │            │      └── security
    │   │            │             │── CorsConfig(C)
    │   │            │             │── SecurityConfig(C)
    │   │            │             │── CustomAccessDeniedHandler(C)
    │   │            │             │── CustomAuthenticationFailureHandler(C)  
    │   │            │             │── CustomAuthenticationSuccessHandler(C)  
    │   │            │             │── CustomAuthenticationProvider(C)
    │   │            │             │── CustomAuthenticationEndPoint(C)
    │   │            │             │── jwt
    │   │            │             │    │── JwtAuthenticationFilter(C)
    │   │            │             │    │── JwtAutorizationFilter(C)
    │   │            │             │    │── JwtProvider(C)
    │   │            │             │    └── JwtProperties(C)
    │   │            │             └── principal
    │   │            │                  │── PrincipalDetail(C)
    │   │            │                  └── PrincipalDetailService(C)
    │   │            └── repository
    │   │                 └── UserRespository(I)
    │   │        
    │   └── resources
    │       ├── templates           
    │       └── application.yaml
```

## [내용]
- JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter
  - [POST] /sign-in 으로 요청 시 작동하는 필터(default : POST, /login)
  - UsernamePasswordAuthenticationFilter는 httpSecurity.formLogin(), [POST] /login [username, password]일때 작동
  - jwt방식을 사용하기 때문에 formLogin().disable() => UsernamePasswordAuthenticationFilter는 동작하지않음
  - UsernamePasswordAuthenticationFilter 상속받아 jwt 사용 시 로그인 용 필터를 구현 => security 에 등록하여 작동
  ```
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
  ```

- JwtAuthorizationFilter extends BasicAuthenticationFilter
  - 인증이나 권한이 필요한 url요청 시 이 필터를 타게됨 
  - => jwt 토큰 검증이 필요한 api, url 요청 시 작동 
  - => jwt 토큰 검증이 필요없는 api, url 설정가능

- 기본작동원리 : 로그인(신원인증)
  - 1. [POST /sign-in, 로그인 요청 (application/json, { "username" : "", "password", ""})
  - 2. JwtAuthenticationFilter 동작
    - request 객체로부터 username, password get
    - UsernamePasswordAuthenticationToken생성,authenticationManager로 인증시도(PrincipalDetailsService - loadUserByUsername() 호출)
      - 성공 시 customAuthenticationSuccessHandler 작동
      - 실패 시 customAuthenticationFailureHandler 작동
  - 3. customAuthenticationSuccessHandler : JWT 생성 및 응답
  
- 기본작동원리 : 권한인가, jwt검증
  - 1. JwtAuthorizationFilter 동작
  - 2. header에서 jwt 토큰 획득
    - 없다면 customAuthenticationEntryPoint 동작
  - 3. jwt 토큰 유효하면 Authentication객체를 생성하고 강제로 시큐리티의 세션에 접근하여 값 저장 => 권한처리를 위함
  - 4. 권한확인
    - 권한이 없다면 customAccessDeniedHandler 작동

- 로그아웃 : REDIS적용이 필요
  - ㄴ