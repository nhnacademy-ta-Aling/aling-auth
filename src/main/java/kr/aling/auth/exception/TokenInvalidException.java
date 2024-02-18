package kr.aling.auth.exception;

/**
 * 유효하지 않은 Token인 경우 발생하는 Exception.
 *
 * @author 이수정
 * @since 1.0
 */
public class TokenInvalidException extends RuntimeException {

    public TokenInvalidException(String message) {
        super("유효하지 않은 JWT 토큰입니다. : " + message);
    }
}
