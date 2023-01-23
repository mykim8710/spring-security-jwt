package spring.security.jwt.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import spring.security.jwt.global.result.CommonResult;
import spring.security.jwt.global.result.error.ErrorCode;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final String redirectUrl;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("sign in fail, api={}", request.getRequestURI());

        if(request.getRequestURI().contains("api")){

            // 해당계정이 없을때
            if (authException instanceof UsernameNotFoundException) {
                sendErrorResponseApiLogin(response, ErrorCode.INVALID_SIGN_IN_INFO);
            }

            // 비밀번호가 틀릴때 BadCredentialsException < AuthenticationException < RuntimeException
            if (authException instanceof BadCredentialsException) {
                sendErrorResponseApiLogin(response, ErrorCode.INVALID_SIGN_IN_INFO);
            }

        } else{
            log.error("미인증 유저 page 접근");

            int httpStatus = HttpServletResponse.SC_UNAUTHORIZED;   // 401 error
            response.setStatus(httpStatus); // Status 설정
            response.sendRedirect(redirectUrl);
        }
    }

    // API login 방식
    private void sendErrorResponseApiLogin(HttpServletResponse response, ErrorCode errorCode) throws HttpMessageNotWritableException, IOException {
        MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
        MediaType jsonMimeType = MediaType.APPLICATION_JSON;
        CommonResult result = CommonResult.createBusinessExceptionResult(errorCode);
        if(jsonConverter.canWrite(result.getClass(), jsonMimeType)) {
            jsonConverter.write(result, jsonMimeType, new ServletServerHttpResponse(response));
        }
    }
}
