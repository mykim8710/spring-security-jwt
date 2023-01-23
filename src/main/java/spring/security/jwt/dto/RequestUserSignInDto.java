package spring.security.jwt.dto;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class RequestUserSignInDto {
    private String username;
    private String password;
}
