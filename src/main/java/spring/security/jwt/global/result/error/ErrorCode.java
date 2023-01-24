package spring.security.jwt.global.result.error;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public enum ErrorCode {
    // authentication error
    NOT_FOUND_USER(400, "A001", "this user is not found."),
    PASSWORD_NOT_MATCH(400, "A002", "password is not matched."),

    // authorization error
    UNAUTHORIZED(401, "A003", "Unauthorized user"), // 로그인 필요(JWT가 유효하지 않음. Security Context내에 설정되지 않음)
    ACCESS_DENIED(403, "A004", "Access is denied"), // 로그인은 했지만 권한 없음

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
