package kr.aling.auth.service.impl;

import java.time.Duration;
import javax.servlet.http.HttpServletRequest;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import kr.aling.auth.properties.JwtProperties;
import kr.aling.auth.provider.JwtProvider;
import kr.aling.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
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

    private final JwtProvider jwtProvider;
    private final JwtProperties jwtProperties;

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * {@inheritDoc}
     */
    @Override
    public HttpHeaders issue(IssueTokenRequestDto requestDto) {
        String userNo = String.valueOf(requestDto.getUserNo());
        String accessToken = jwtProvider.createToken(userNo, requestDto.getRoles(), jwtProperties.getAtkExpireTime().toMillis());
        String refreshToken = jwtProvider.createToken(userNo, requestDto.getRoles(), jwtProperties.getRtkExpireTime().toMillis());

        redisTemplate.opsForValue().set(userNo, refreshToken);

        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtProperties.getAtkHeaderName(), accessToken);
        headers.add(jwtProperties.getRtkHeaderName(), refreshToken);
        return headers;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TokenPayloadDto getReissuePayload(HttpServletRequest request) {
        String refreshToken = request.getHeader(jwtProperties.getRtkHeaderName());

        TokenPayloadDto payload = jwtProvider.parseToken(refreshToken);
        if (refreshToken.equals(redisTemplate.opsForValue().get(payload.getUserNo()))) {
            throw new RefreshTokenInvalidException("저장소에 존재하지 않거나 일치하지 않습니다.");
        }
        return payload;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HttpHeaders reissue(TokenPayloadDto payloadDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtProperties.getAtkHeaderName(), jwtProvider.createToken(
                payloadDto.getUserNo(), payloadDto.getRoles(), jwtProperties.getAtkExpireTime().toMillis()));
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
