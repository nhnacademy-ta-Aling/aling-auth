package kr.aling.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import kr.aling.auth.properties.JwtProperties;
import kr.aling.auth.provider.JwtProvider;
import kr.aling.auth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;

class JwtServiceImplTest {

    private JwtService jwtService;

    private JwtProvider jwtProvider;
    private JwtProperties jwtProperties;
    private RedisTemplate<String, Object> redisTemplate;

    @BeforeEach
    void setUp() {
        jwtProvider = mock(JwtProvider.class);
        redisTemplate = mock(RedisTemplate.class);
        jwtProperties = mock(JwtProperties.class);

        jwtService = new JwtServiceImpl(
                jwtProvider,
                jwtProperties,
                redisTemplate
        );
    }

    @Test
    @DisplayName("AccessToken, RefreshToken 발급 성공")
    void issue() {
        // given
        String accessToken = "######";
        String refreshToken = "@@@@@@";
        IssueTokenRequestDto requestDto = new IssueTokenRequestDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProperties.getAtkExpireTime()).thenReturn(Duration.ofMillis(1000));
        when(jwtProperties.getRtkExpireTime()).thenReturn(Duration.ofMillis(10000));
        when(jwtProperties.getAtkHeaderName()).thenReturn("ACCESS_TOKEN");
        when(jwtProperties.getRtkHeaderName()).thenReturn("REFRESH_TOKEN");

        when(jwtProvider.createToken(anyString(), anyList(), eq(Duration.ofMillis(1000).toMillis()))).thenReturn(accessToken);
        when(jwtProvider.createToken(anyString(), anyList(), eq(Duration.ofMillis(10000).toMillis()))).thenReturn(refreshToken);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        doNothing().when(valueOps).set(anyString(), anyList());

        // when
        HttpHeaders result =  jwtService.issue(requestDto);

        // then
        assertThat(result).isNotNull();
        assertThat(result.get("ACCESS_TOKEN").get(0)).isEqualTo(accessToken);
        assertThat(result.get("REFRESH_TOKEN").get(0)).isEqualTo(refreshToken);

        verify(jwtProvider, times(2)).createToken(anyString(), anyList(), anyLong());
        verify(redisTemplate, times(1)).opsForValue();
    }

    @Test
    @DisplayName("Reissue용 페이로드 반환 성공")
    void getReissuePayload() {
        // given
        String refreshToken = "@@@@@@";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(jwtProperties.getRtkHeaderName()).thenReturn("REFRESH_TOKEN");
        when(request.getHeader(anyString())).thenReturn(refreshToken);

        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.parseToken(refreshToken)).thenReturn(tokenPayloadDto);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(refreshToken);

        // when
        TokenPayloadDto result =  jwtService.getReissuePayload(request);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getUserNo()).isEqualTo(tokenPayloadDto.getUserNo());
        assertThat(result.getRoles()).isEqualTo(tokenPayloadDto.getRoles());

        verify(jwtProperties, times(1)).getRtkHeaderName();
        verify(jwtProvider, times(1)).parseToken(anyString());
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).get(anyString());
    }

    @Test
    @DisplayName("Reissue용 페이로드 반환 실패 - 저장소에 존재하지 않는 토큰")
    void getReissuePayload_notExistsRefreshToken() {
        // given
        String refreshToken = "@@@@@@";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(jwtProperties.getRtkHeaderName()).thenReturn("REFRESH_TOKEN");
        when(request.getHeader(anyString())).thenReturn(refreshToken);

        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.parseToken(refreshToken)).thenReturn(tokenPayloadDto);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn("");

        // when
        assertThatThrownBy(() -> jwtService.getReissuePayload(request))
                .isInstanceOf(RefreshTokenInvalidException.class);

        // then
        verify(jwtProperties, times(1)).getRtkHeaderName();
        verify(jwtProvider, times(1)).parseToken(anyString());
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).get(anyString());
    }

    @Test
    @DisplayName("AccessToken 재발급 성공")
    void reissue() {
        // given
        String accessToken = "######";
        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProperties.getAtkExpireTime()).thenReturn(Duration.ofMillis(1000));
        when(jwtProperties.getRtkExpireTime()).thenReturn(Duration.ofMillis(10000));
        when(jwtProperties.getAtkHeaderName()).thenReturn("ACCESS_TOKEN");
        when(jwtProperties.getRtkHeaderName()).thenReturn("REFRESH_TOKEN");

        when(jwtProvider.createToken(anyString(), anyList(), anyLong())).thenReturn(accessToken);

        // when
        HttpHeaders result =  jwtService.reissue(tokenPayloadDto);

        // then
        assertThat(result).isNotNull();
        assertThat(result.get("ACCESS_TOKEN").get(0)).isEqualTo(accessToken);

        verify(jwtProvider, times(1)).createToken(anyString(), anyList(), anyLong());
    }

    @Test
    @DisplayName("로그아웃 성공")
    void logout() {
        // given
        Long userNo = 1L;

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.getAndExpire(anyString(), any())).thenReturn(null);

        // when
        jwtService.logout(userNo);

        // then
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).getAndExpire(anyString(), any());
    }
}