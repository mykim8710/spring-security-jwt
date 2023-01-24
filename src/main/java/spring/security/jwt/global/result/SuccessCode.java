package spring.security.jwt.global.result;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public enum SuccessCode {
    // Common
    COMMON(200, "", "OK"),
    SIGN_IN(200, "", "sign in ok"),




    ;

    private int status;
    private String code;
    private String message;

    SuccessCode(int status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
