package spring.security.jwt.global.result.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import spring.security.jwt.global.result.CommonResult;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {
    /* @Service Exception */
    @ExceptionHandler(BusinessException.class)
    protected ResponseEntity<CommonResult> businessExceptionHandle(final BusinessException e) {
        log.error(e.getErrorCode().getCode() + " : " + e.getErrorCode().getMessage());

        final ErrorCode errorCode = e.getErrorCode();
        CommonResult response = CommonResult.createBusinessExceptionResult(errorCode);

        log.error("errorCode > " +errorCode);
        log.error("response > " +response);

        return new ResponseEntity<>(response, HttpStatus.valueOf(errorCode.getStatus()));
    }
}

