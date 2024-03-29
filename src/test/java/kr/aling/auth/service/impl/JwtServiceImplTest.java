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

import io.jsonwebtoken.Claims;
import java.time.Duration;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import kr.aling.auth.jwt.JwtProvider;
import kr.aling.auth.jwt.JwtUtils;
import kr.aling.auth.properties.AccessProperties;
import kr.aling.auth.properties.RefreshProperties;
import kr.aling.auth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.password.PasswordEncoder;

class JwtServiceImplTest {

    private JwtService jwtService;

    private AccessProperties accessProperties;
    private RefreshProperties refreshProperties;

    private JwtProvider jwtProvider;
    private JwtUtils jwtUtils;

    private RedisTemplate<String, Object> redisTemplate;

    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        accessProperties = mock(AccessProperties.class);
        refreshProperties = mock(RefreshProperties.class);
        jwtProvider = mock(JwtProvider.class);
        jwtUtils = mock(JwtUtils.class);
        redisTemplate = mock(RedisTemplate.class);
        passwordEncoder = mock(PasswordEncoder.class);

        when(accessProperties.getSecret()).thenReturn(
                "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretkk");
        when(accessProperties.getExpireTime()).thenReturn(Duration.ofMillis(1000));
        when(refreshProperties.getSecret()).thenReturn(
                "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretkk");
        when(refreshProperties.getHeaderName()).thenReturn("X-Refresh-Token");
        when(refreshProperties.getExpireTime()).thenReturn(Duration.ofMillis(10000));

        jwtService = new JwtServiceImpl(
                accessProperties,
                refreshProperties,
                jwtProvider,
                jwtUtils,
                redisTemplate,
                passwordEncoder
        );
    }

    @Test
    @DisplayName("AccessToken, RefreshToken 발급 성공")
    void issue() {
        // given
        String accessToken = "######";
        String refreshToken = "@@@@@@";
        IssueTokenRequestDto requestDto = new IssueTokenRequestDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.createToken(anyString(), anyString(), anyList(),
                eq(Duration.ofMillis(1000).toMillis()))).thenReturn(accessToken);
        when(jwtProvider.createToken(anyString(), anyString(), anyList(),
                eq(Duration.ofMillis(10000).toMillis()))).thenReturn(refreshToken);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        doNothing().when(valueOps).set(anyString(), anyList());

        // when
        HttpHeaders result = jwtService.issue(requestDto);

        // then
        assertThat(result).isNotNull();
        assertThat(result.get("Authorization").get(0)).isEqualTo("Bearer " + accessToken);
        assertThat(result.get("X-Refresh-Token").get(0)).isEqualTo(refreshToken);

        verify(jwtProvider, times(2)).createToken(anyString(), anyString(), anyList(), anyLong());
        verify(redisTemplate, times(1)).opsForValue();
    }

    @Test
    @DisplayName("Reissue용 페이로드 반환 성공")
    void getReissuePayload() {
        // given
        String refreshToken = "@@@@@@";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getHeader(anyString())).thenReturn(refreshToken);

        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("1");
        when(claims.get("roles")).thenReturn(List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtUtils.parseToken(anyString(), eq(refreshToken))).thenReturn(claims);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(refreshToken);

        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        // when
        TokenPayloadDto result = jwtService.getReissuePayload(request);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getUserNo()).isEqualTo(tokenPayloadDto.getUserNo());
        assertThat(result.getRoles()).isEqualTo(tokenPayloadDto.getRoles());

        verify(refreshProperties, times(1)).getHeaderName();
        verify(jwtUtils, times(1)).parseToken(anyString(), anyString());
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).get(anyString());
        verify(passwordEncoder, times(1)).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("Reissue용 페이로드 반환 실패 - 저장소 내의 토큰과 일치하지 않는 경우")
    void getReissuePayload_notMatchRequestToken() {
        // given
        String refreshToken = "@@@@@@";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getHeader(anyString())).thenReturn(refreshToken);

        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("1");
        when(claims.get("roles")).thenReturn(List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtUtils.parseToken(anyString(), eq(refreshToken))).thenReturn(claims);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(refreshToken);

        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        // when
        assertThatThrownBy(() -> jwtService.getReissuePayload(request))
                .isInstanceOf(RefreshTokenInvalidException.class);

        // then
        verify(refreshProperties, times(1)).getHeaderName();
        verify(jwtUtils, times(1)).parseToken(anyString(), anyString());
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).get(anyString());
        verify(passwordEncoder, times(1)).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("Reissue용 페이로드 반환 실패 - 저장소에 존재하지 않는 토큰")
    void getReissuePayload_notExistsRefreshToken() {
        // given
        String refreshToken = "@@@@@@";
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getHeader(anyString())).thenReturn(refreshToken);

        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("1");
        when(claims.get("roles")).thenReturn(List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtUtils.parseToken(anyString(), eq(refreshToken))).thenReturn(claims);

        ValueOperations<String, Object> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn("");

        // when
        assertThatThrownBy(() -> jwtService.getReissuePayload(request))
                .isInstanceOf(RefreshTokenInvalidException.class);

        // then
        verify(refreshProperties, times(1)).getHeaderName();
        verify(jwtUtils, times(1)).parseToken(anyString(), anyString());
        verify(redisTemplate, times(1)).opsForValue();
        verify(valueOps, times(1)).get(anyString());
    }

    @Test
    @DisplayName("AccessToken 재발급 성공")
    void reissue() {
        // given
        String accessToken = "######";
        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtProvider.createToken(anyString(), anyString(), anyList(), anyLong())).thenReturn(accessToken);

        // when
        HttpHeaders result = jwtService.reissue(tokenPayloadDto);

        // then
        assertThat(result).isNotNull();
        assertThat(result.get("Authorization").get(0)).isEqualTo("Bearer " + accessToken);

        verify(jwtProvider, times(1)).createToken(anyString(), anyString(), anyList(), anyLong());
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