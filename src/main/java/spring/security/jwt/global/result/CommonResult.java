package spring.security.jwt.global.result;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring.security.jwt.global.result.error.ErrorCode;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class CommonResult<T> {
    private int status;     // http Status(2XX, 3XX....)
    private String code; 	// 지정 code
    private String message; // 메세지
    private T data;

    // Success CommonResult have return data
    public CommonResult(SuccessCode successCode) {
        this.status = successCode.getStatus();
        this.code = successCode.getCode();
        this.message = successCode.getMessage();
    }

    // Success CommonResult have return data
    public CommonResult(T data, SuccessCode successCode) {
        this.status = successCode.getStatus();
        this.code = successCode.getCode();
        this.message = successCode.getMessage();
        this.data = data;
    }

    // CommonResult for Error(Business exception)
    public static CommonResult createBusinessExceptionResult(ErrorCode errorCode) {
        CommonResult commonResult = new CommonResult();
        commonResult.setStatus(errorCode.getStatus());
        commonResult.setCode(errorCode.getCode());
        commonResult.setMessage(errorCode.getMessage());
        return commonResult;
    }

    private void setStatus(int status) {
        this.status = status;
    }

    private void setCode(String code) {
        this.code = code;
    }

    private void setMessage(String message) {
        this.message = message;
    }

    private void setData(T data) {
        this.data = data;
    }
}