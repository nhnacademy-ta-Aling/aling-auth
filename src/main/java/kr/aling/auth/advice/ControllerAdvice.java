package kr.aling.auth.advice;

import io.jsonwebtoken.ExpiredJwtException;
import kr.aling.auth.exception.TokenInvalidException;
import kr.aling.auth.exception.TokenNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
     * Http Status 401에 해당하는 예외를 공통 처리합니다.
     *
     * @param e 401에 해당하는 예외
     * @return 401 status response
     * @author 이수정
     * @since 1.0
     */
    @ExceptionHandler({TokenInvalidException.class, ExpiredJwtException.class, TokenNotFoundException.class})
    public ResponseEntity<String> handleBadRequestException(Exception e) {
        log.error("[{}] {}", HttpStatus.UNAUTHORIZED, e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }
}
