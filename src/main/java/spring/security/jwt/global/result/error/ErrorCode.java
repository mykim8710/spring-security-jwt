package spring.security.jwt.global.result.error;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public enum ErrorCode {
    // sign in error
    INVALID_SIGN_IN_INFO(400, "S001", "username or password is not matched."),

    ;


    private int status;
    private String code;
    private String message;

    ErrorCode(int status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }

}
