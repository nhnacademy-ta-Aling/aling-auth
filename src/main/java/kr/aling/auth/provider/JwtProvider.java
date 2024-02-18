package kr.aling.auth.provider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.List;
import kr.aling.auth.dto.request.TokenPayloadDto;
import kr.aling.auth.exception.TokenInvalidException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰에 관련된 작업을 제공하는 Provider class.
 *
 * @author 이수정
 * @since 1.0
 */
@Component
public class JwtProvider {

    private final Key secretKey;
    private final JwtParser jwtParser;

    /**
     * JwtProvider 생성자.
     * secret key 값을 base64 decode해 Key를 생성합니다.
     * JWT 토큰을 파싱할 JwtParser를 생성합니다.
     *
     * @param secretKey 디코딩할 secretKey 문자열
     * @author 이수정
     * @since 1.0
     */
    public JwtProvider(@Value("${aling.security.secretKey}") String secretKey) {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        this.secretKey = Keys.hmacShaKeyFor(bytes);
        this.jwtParser = Jwts.parserBuilder().setSigningKey(bytes).build();
    }

    /**
     * JWT 토큰을 생성합니다.
     * claims -> sub = 회원 식별, roles = 회원 권한
     *
     * @param userNo 토큰을 발급받는 회원의 번호
     * @param roles 토큰을 발급받는 회원의 권한
     * @return 생성된 토큰
     * @author 이수정
     * @since 1.0
     */
    public String createToken(Long userNo, List<String> roles, long expireTime) {
        Claims claims = Jwts.claims().setSubject(String.valueOf(userNo));
        claims.put("roles", roles);

        Date now = new Date();
        claims.setIssuedAt(now);
        claims.setExpiration(new Date(now.getTime() + expireTime));

        return Jwts.builder()
                .setClaims(claims)
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * JWT 토큰을 파싱해 회원 식별 정보와 권한 정보를 반환합니다.
     *
     * @param token 디코딩할 토큰
     * @return 회원 식별 정보와 권한 정보를 담은 Dto
     * @author 이수정
     * @since 1.0
     */
    public TokenPayloadDto parseToken(String token) {
        try {
            Claims claims = jwtParser.parseClaimsJws(token).getBody();
            return new TokenPayloadDto(
                    Long.parseLong(claims.getSubject()),
                    (List<String>) claims.get("roles")
            );
        } catch (ExpiredJwtException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenInvalidException(e.getMessage());
        }
    }
}
