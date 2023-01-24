package spring.security.jwt.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.jwt.config.security.principal.PrincipalDetail;

@Slf4j
@RestController
public class UserApiController {
    @GetMapping("/test")
    public String test() {
        return "test";
    }

    // ROLE_USER, ROLE_MANAGER, ROLE_ADMIN 접근가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication) {
        log.info("[GET] /api/v1/user");

        PrincipalDetail principal = (PrincipalDetail)authentication.getPrincipal();
        System.out.println(principal.getUser().getId());
        System.out.println(principal.getUser().getUsername());
        System.out.println(principal.getUser().getRoles());

        return "user";
    }

    // ROLE_MANAGER, ROLE_ADMIN 접근가능
    @GetMapping("/api/v1/manager")
    public String manager(Authentication authentication) {
        log.info("[GET] /api/v1/manager");

        PrincipalDetail principal = (PrincipalDetail)authentication.getPrincipal();
        System.out.println(principal.getUser().getId());
        System.out.println(principal.getUser().getUsername());
        System.out.println(principal.getUser().getRoles());

        return "manager";
    }

    // ROLE_ADMIN 접근가능
    @GetMapping("/api/v1/admin")
    public String admin(Authentication authentication) {
        log.info("[GET] /api/v1/admin");

        PrincipalDetail principal = (PrincipalDetail)authentication.getPrincipal();
        System.out.println(principal.getUser().getId());
        System.out.println(principal.getUser().getUsername());
        System.out.println(principal.getUser().getRoles());

        return "admin";
    }
}
