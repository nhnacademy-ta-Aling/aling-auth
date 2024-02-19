package kr.aling.auth.exception;

/**
 * 유효하지 않은 RefreshToken인 경우 발생하는 Exception.
 *
 * @author 이수정
 * @since 1.0
 */
public class RefreshTokenInvalidException extends RuntimeException {

    public RefreshTokenInvalidException(String message) {
        super("유효하지 않은 Refresh 토큰 : " + message);
    }
}
