package kr.aling.auth.service.impl;

import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.provider.JwtProvider;
import kr.aling.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
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

    private static final long ACCESS_TOKEN_EXPIRE_TIME = 30 * 60 * 1000L;
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 14 * 24 * 60 * 60 * 1000L;

    private static final String ACCESS_TOKEN_REDIS_KEY = "aling_access";
    private static final String REFRESH_TOKEN_REDIS_KEY = "aling_refresh";

    private final JwtProvider jwtProvider;

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * {@inheritDoc}
     */
    @Override
    public String createAccessToken(IssueTokenRequestDto requestDto) {
        String accessToken = jwtProvider.createToken(requestDto.getUserNo(), requestDto.getRoles(), ACCESS_TOKEN_EXPIRE_TIME);

        redisTemplate.opsForSet().add(ACCESS_TOKEN_REDIS_KEY, accessToken);

        return accessToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createRefreshToken(IssueTokenRequestDto requestDto) {
        String refreshToken = jwtProvider.createToken(requestDto.getUserNo(), requestDto.getRoles(), REFRESH_TOKEN_EXPIRE_TIME);

        redisTemplate.opsForSet().add(REFRESH_TOKEN_REDIS_KEY, refreshToken);

        return refreshToken;
    }
}
