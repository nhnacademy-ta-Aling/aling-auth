package kr.aling.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import kr.aling.auth.dto.request.TokenPayloadDto;
import kr.aling.auth.provider.JwtProvider;
import kr.aling.auth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;

class JwtServiceImplTest {

    private JwtService jwtService;

    private JwtProvider jwtProvider;
    private RedisTemplate<String, Object> redisTemplate;

    @BeforeEach
    void setUp() {
        jwtProvider = mock(JwtProvider.class);
        redisTemplate = mock(RedisTemplate.class);

        jwtService = new JwtServiceImpl(
                jwtProvider,
                redisTemplate
        );
    }

    @Test
    @DisplayName("Access Token 발급 성공")
    void createAccessToken() {
        // given
        String accessToken = "######";
        SetOperations<String, Object> setOps = mock(SetOperations.class);
        TokenPayloadDto requestDto = new TokenPayloadDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.createToken(anyLong(), anyList(), anyLong())).thenReturn(accessToken);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.add(anyString(), any())).thenReturn(null);

        // when
        String result =  jwtService.createAccessToken(requestDto);

        // then
        assertThat(result).isEqualTo(accessToken);

        verify(jwtProvider, times(1)).createToken(anyLong(), anyList(), anyLong());
        verify(redisTemplate, times(1)).opsForSet();
        verify(setOps, times(1)).add(anyString(), any());
    }

    @Test
    @DisplayName("Refresh Token 발급 성공")
    void createRefreshToken() {
        // given
        String refreshToken = "######";
        SetOperations<String, Object> setOps = mock(SetOperations.class);
        TokenPayloadDto requestDto = new TokenPayloadDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.createToken(anyLong(), anyList(), anyLong())).thenReturn(refreshToken);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.add(anyString(), any())).thenReturn(null);

        // when
        String result =  jwtService.createRefreshToken(requestDto);

        // then
        assertThat(result).isEqualTo(refreshToken);

        verify(jwtProvider, times(1)).createToken(anyLong(), anyList(), anyLong());
        verify(redisTemplate, times(1)).opsForSet();
        verify(setOps, times(1)).add(anyString(), any());
    }
}