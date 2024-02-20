package kr.aling.auth.advice;

import javax.validation.ConstraintViolationException;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 전역 예외 핸들링 class.
 *
 * @author 이수정
 * @since 1.0
 */
@Slf4j
@RestControllerAdvice
public class ControllerAdvice {

    /**
     * Http Status 400에 해당하는 예외를 공통 처리합니다.
     *
     * @param e 400에 해당하는 예외
     * @return 400 status response
     * @author 이수정
     * @since 1.0
     */
    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class, IllegalArgumentException.class})
    public ResponseEntity<String> handleBadRequestException(Exception e) {
        log.error("[{}] {}", HttpStatus.BAD_REQUEST, e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }

    /**
     * Http Status 401에 해당하는 예외를 공통 처리합니다.
     *
     * @param e 401에 해당하는 예외
     * @return 401 status response
     * @author 이수정
     * @since 1.0
     */
    @ExceptionHandler(RefreshTokenInvalidException.class)
    public ResponseEntity<String> handleUnauthorizedException(Exception e) {
        log.error("[{}] {}", HttpStatus.UNAUTHORIZED, e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    /**
     * Http Status 500에 해당하는 예외를 공통 처리합니다. 분류되지 않은 예외는 모두 500 처리됩니다.
     *
     * @param e 500에 해당하는 예외
     * @return 500 status response
     * @author 이수정
     * @since 1.0
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleInternalServerError(Exception e) {
        log.error("[{}] {}", HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        return ResponseEntity.internalServerError().body(e.getMessage());
    }
}