package kr.aling.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰 파싱해 정보를 얻는 Util class.
 *
 * @author 이수정
 * @since 1.0
 */
@Component
public class JwtUtils {

    /**
     * JWT 토큰을 파싱해 Claims 객체를 반환합니다.
     *
     * @param secretKey 토큰에 따른 secret key
     * @param token     디코딩할 토큰
     * @return 회원 번호와 역할을 담은 Claims
     * @author 이수정
     * @since 1.0
     */
    public Claims parseToken(String secretKey, String token) {
        return Jwts.parserBuilder().setSigningKey(Decoders.BASE64.decode(secretKey)).build()
                .parseClaimsJws(token).getBody();
    }
}
