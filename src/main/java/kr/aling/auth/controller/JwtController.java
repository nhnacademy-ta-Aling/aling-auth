package kr.aling.auth.controller;

import io.jsonwebtoken.ExpiredJwtException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import kr.aling.auth.dto.request.TokenPayloadDto;
import kr.aling.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * JWT 발급 및 검증 RestController.
 *
 * @author 이수정
 * @since 1.0
 */
@RequiredArgsConstructor
@RequestMapping("/api/v1/jwt")
@RestController
public class JwtController {

    public static final String ACCESS_TOKEN_HEADER_NAME = "ACCESS_TOKEN";
    public static final String REFRESH_TOKEN_HEADER_NAME = "REFRESH_TOKEN";

    private final JwtService jwtService;

    /**
     * 로그인 시 AccessToken과 RefreshToken을 생성합니다.
     *
     * @param requestDto 로그인 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT 토큰을 헤더로 추가 후 응답
     * @author 이수정
     * @since 1.0
     */
    @GetMapping("/issue")
    public ResponseEntity<Void> issueToken(@RequestBody @Valid TokenPayloadDto requestDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(ACCESS_TOKEN_HEADER_NAME, jwtService.createAccessToken(requestDto));
        headers.add(REFRESH_TOKEN_HEADER_NAME, jwtService.createRefreshToken(requestDto));

        return ResponseEntity.ok().headers(headers).build();
    }

    /**
     * AccessToken의 유효성을 검증하고, 존재하면 200 OK를 반환합니다.
     * 만료라면 RefreshToken으로 재발급 후 200 OK, Refresh 토큰이 없다면 401 UNAUTHORIZED륿 반환합니다.
     *
     * @param request 요청의 헤더를 얻기 위한 HttpServletRequest 객체
     * @return 유효 여부
     * @author 이수정
     * @since 1.0
     */
    @GetMapping("/verify")
    public ResponseEntity<TokenPayloadDto> verifyToken(HttpServletRequest request) {
        String accessToken = request.getHeader(ACCESS_TOKEN_HEADER_NAME);
        String refreshToken = request.getHeader(REFRESH_TOKEN_HEADER_NAME);

        TokenPayloadDto response;
        try {
            response = jwtService.verifyToken(accessToken);
        } catch (ExpiredJwtException e) {
            accessToken = jwtService.reissueToken(refreshToken);
            response = jwtService.verifyToken(accessToken);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.add(ACCESS_TOKEN_HEADER_NAME, accessToken);
        headers.add(REFRESH_TOKEN_HEADER_NAME, refreshToken);

        return ResponseEntity.ok().headers(headers).body(response);
    }

}
