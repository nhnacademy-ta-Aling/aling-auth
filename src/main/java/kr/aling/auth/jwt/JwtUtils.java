package kr.aling.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰 파싱해 정보를 얻는 Util class.
 *
 * @author 이수정
 * @since 1.0
 */
@Component
public class JwtUtils {

    private final JwtParser jwtParser;

    /**
     * JwtUtils 생성자. JWT 토큰을 파싱할 JwtParser를 생성합니다.
     *
     * @param secretKey 디코딩할 secretKey 문자열
     * @author 이수정
     * @since 1.0
     */
    public JwtUtils(@Value("${aling.security.secret}") String secretKey) {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.jwtParser = Jwts.parserBuilder().setSigningKey(bytes).build();
    }

    /**
     * JWT 토큰을 파싱해 Claims 객체를 반환합니다.
     *
     * @param token 디코딩할 토큰
     * @return 회원 번호와 역할을 담은 Claims
     * @author 이수정
     * @since 1.0
     */
    public Claims parseToken(String token) {
        return jwtParser.parseClaimsJws(token).getBody();
    }
}
