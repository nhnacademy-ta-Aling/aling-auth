package kr.aling.auth.service.impl;

import kr.aling.auth.dto.request.TokenPayloadDto;
import kr.aling.auth.exception.TokenNotFoundException;
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
    public String createAccessToken(TokenPayloadDto requestDto) {
        String accessToken = jwtProvider.createToken(requestDto.getUserNo(), requestDto.getRoles(), ACCESS_TOKEN_EXPIRE_TIME);

        redisTemplate.opsForSet().add(ACCESS_TOKEN_REDIS_KEY, accessToken);

        return accessToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createRefreshToken(TokenPayloadDto requestDto) {
        String refreshToken = jwtProvider.createToken(requestDto.getUserNo(), requestDto.getRoles(), REFRESH_TOKEN_EXPIRE_TIME);

        redisTemplate.opsForSet().add(REFRESH_TOKEN_REDIS_KEY, refreshToken);

        return refreshToken;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TokenPayloadDto verifyToken(String token) {
        if (!isExistsToken(token, ACCESS_TOKEN_REDIS_KEY)) {
            throw new TokenNotFoundException();
        }
        return jwtProvider.parseToken(token);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String reissueToken(String refreshToken) {
        if (!isExistsToken(refreshToken, REFRESH_TOKEN_REDIS_KEY)) {
            throw new TokenNotFoundException();
        }
        return createAccessToken(jwtProvider.parseToken(refreshToken));
    }


    /**
     * JWT 토큰이 레디스 내에 존재하는지 확인합니다.
     *
     * @param token 존재여부를 확인할 토큰
     * @return 토큰의 존재여부
     * @author 이수정
     * @since 1.0
     */
    private boolean isExistsToken(String token, String key) {
        return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(key, token));
    }
}
