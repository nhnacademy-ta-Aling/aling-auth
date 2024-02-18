package kr.aling.auth.exception;

/**
 * 저장소 내에서 찾을 수 없는 Token인 경우 발생하는 Exception.
 *
 * @author 이수정
 * @since 1.0
 */
public class TokenNotFoundException extends RuntimeException {

    public TokenNotFoundException() {
        super("저장소 내에서 찾을 수 없는 토큰입니다.");
    }
}
