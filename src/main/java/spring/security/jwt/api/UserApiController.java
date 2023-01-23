package spring.security.jwt.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class UserApiController {

    @PostMapping("/token")
    public String home() {
        log.info("[POST] /token");
        return "tokenTest";
    }
}
