package spring.security.jwt.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import spring.security.jwt.config.auth.PrincipalDetailService;

@Slf4j
@RequiredArgsConstructor
//@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final PrincipalDetailService principalDetailService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("AuthenticationProvider 구현");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        System.out.println("username = " + username);
        System.out.println("password = " + password);


        UserDetails userDetails = principalDetailService.loadUserByUsername(username);

        // 비밀번호가 미일치 throw Exception
        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
