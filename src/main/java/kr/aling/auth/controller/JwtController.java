package kr.aling.auth.controller;

import java.time.Duration;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.exception.RefreshTokenInvalidException;
import kr.aling.auth.properties.JwtProperties;
import kr.aling.auth.provider.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JWT 발급 및 검증 RestController.
 *
 * @author 이수정
 * @since 1.0
 */
@Validated
@RequiredArgsConstructor
@RequestMapping("/api/v1/jwt")
@RestController
public class JwtController {

    private final JwtProvider jwtProvider;
    private final JwtProperties jwtProperties;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * 유저 번호와 권한을 받아 AccessToken, RefreshToken 헤더를 생성해 반환합니다.
     *
     * @param requestDto 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT 토큰을 헤더로 추가 후 응답
     * @author 이수정
     * @since 1.0
     */
    @GetMapping("/issue")
    public ResponseEntity<Void> issue(IssueTokenRequestDto requestDto) {
        String userNo = String.valueOf(requestDto.getUserNo());
        String accessToken = jwtProvider.createToken(userNo, requestDto.getRoles(), jwtProperties.getAtkExpireTime().toMillis());
        String refreshToken = jwtProvider.createToken(userNo, requestDto.getRoles(), jwtProperties.getRtkExpireTime().toMillis());

        redisTemplate.opsForValue().set(userNo, refreshToken);

        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtProperties.getAtkHeaderName(), accessToken);
        headers.add(jwtProperties.getRtkHeaderName(), refreshToken);

        return ResponseEntity.ok().headers(headers).build();
    }

    /**
     * RefreshToken을 통해 새로운 AccessToken을 발급받습니다.
     *
     * @param request 요청의 헤더를 얻기 위한 HttpServletRequest 객체
     * @return 새로운 AccessToken을 담은 헤더
     * @author 이수정
     * @since 1.0
     */
    @GetMapping("/reissue")
    public ResponseEntity<Void> reissue(HttpServletRequest request) {
        String refreshToken = request.getHeader(jwtProperties.getRtkHeaderName());

        TokenPayloadDto payload;
        try {
            payload = jwtProvider.parseToken(refreshToken);
        } catch (Exception e) {
            throw new RefreshTokenInvalidException(e.getMessage());
        }

        if (!refreshToken.equals(redisTemplate.opsForValue().get(payload.getUserNo()))) {
            throw new RefreshTokenInvalidException("저장소에 존재하지 않거나 일치하지 않습니다.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.add(jwtProperties.getAtkHeaderName(), jwtProvider.createToken(
                payload.getUserNo(), payload.getRoles(), jwtProperties.getAtkExpireTime().toMillis()));
        return ResponseEntity.ok().headers(headers).build();
    }

    /**
     * 로그아웃 요청 시 레디스 내 RefreshToken을 만료처리합니다.
     *
     * @param userNo 만료처리할 RefreshToken의 redis key
     * @return 200 ok
     * @author 이수정
     * @since 1.0
     */
    @GetMapping("/logout")
    public ResponseEntity<Void> logout(@RequestParam @NotNull @Positive Long userNo) {
        redisTemplate.opsForValue().getAndExpire(String.valueOf(userNo), Duration.ZERO);
        return ResponseEntity.ok().build();
    }
}
