package kr.aling.auth.service.impl;

import io.jsonwebtoken.Claims;
import java.time.Duration;
import java.util.List;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import kr.aling.auth.jwt.JwtProvider;
import kr.aling.auth.jwt.JwtUtils;
import kr.aling.auth.properties.AccessProperties;
import kr.aling.auth.properties.RefreshProperties;
import kr.aling.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * JWT 발급 및 검증 Service 구현체.
 *
 * @author 이수정
 * @since 1.0
 */
@RequiredArgsConstructor
@Service
public class JwtServiceImpl implements JwtService {

    private static final String BEARER = "Bearer ";

    private final AccessProperties accessProperties;
    private final RefreshProperties refreshProperties;

    private final JwtProvider jwtProvider;
    private final JwtUtils jwtUtils;

    private final RedisTemplate<String, Object> redisTemplate;

    private final PasswordEncoder passwordEncoder;

    /**
     * {@inheritDoc}
     */
    @Override
    public HttpHeaders issue(IssueTokenRequestDto requestDto) {
        String userNo = String.valueOf(requestDto.getUserNo());
        String accessToken = jwtProvider.createToken(accessProperties.getSecret(), userNo, requestDto.getRoles(),
                accessProperties.getExpireTime().toMillis());
        String refreshToken = jwtProvider.createToken(refreshProperties.getSecret(), userNo, requestDto.getRoles(),
                refreshProperties.getExpireTime().toMillis());

        redisTemplate.opsForValue().set(userNo, passwordEncoder.encode(refreshToken));

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, BEARER + accessToken);
        headers.add(refreshProperties.getHeaderName(), refreshToken);
        return headers;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TokenPayloadDto getReissuePayload(String refreshToken) {
        Claims claims = jwtUtils.parseToken(refreshProperties.getSecret(), refreshToken);
        TokenPayloadDto payload = new TokenPayloadDto(claims.getSubject(), (List<String>) claims.get("roles"));
        if (!passwordEncoder.matches(refreshToken, (String) redisTemplate.opsForValue().get(payload.getUserNo()))) {
            throw new RefreshTokenInvalidException("해당 Refresh Token이 저장소에 존재하지 않거나 일치하지 않습니다.");
        }
        return payload;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HttpHeaders reissue(TokenPayloadDto payloadDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION,
                BEARER + jwtProvider.createToken(accessProperties.getSecret(), payloadDto.getUserNo(),
                        payloadDto.getRoles(), accessProperties.getExpireTime().toMillis()));
        return headers;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void logout(Long userNo) {
        redisTemplate.opsForValue().getAndExpire(String.valueOf(userNo), Duration.ZERO);
    }
}
