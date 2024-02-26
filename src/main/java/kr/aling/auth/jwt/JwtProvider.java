package kr.aling.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰에 관련된 작업을 제공하는 Provider class.
 *
 * @author 이수정
 * @since 1.0
 */
@Component
public class JwtProvider {

    /**
     * JWT 토큰을 생성합니다. claims -> sub = 회원 식별, roles = 회원 권한
     *
     * @param secretKey  토큰에 따른 secret key
     * @param userNo     토큰을 발급받는 회원의 번호
     * @param roles      토큰을 발급받는 회원의 권한
     * @param expireTime 토큰 만료 시간
     * @return 생성된 토큰
     * @author 이수정
     * @since 1.0
     */
    public String createToken(String secretKey, String userNo, List<String> roles, long expireTime) {
        Claims claims = Jwts.claims().setSubject(userNo);
        claims.put("roles", roles);

        Date now = new Date();
        claims.setIssuedAt(now);
        claims.setExpiration(new Date(now.getTime() + expireTime));

        return Jwts.builder()
                .setClaims(claims)
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)), SignatureAlgorithm.HS512)
                .compact();
    }
}
