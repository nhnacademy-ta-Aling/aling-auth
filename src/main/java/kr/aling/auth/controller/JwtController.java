package kr.aling.auth.controller;

import javax.validation.Valid;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
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
    public ResponseEntity<Void> issueToken(@RequestBody @Valid IssueTokenRequestDto requestDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(ACCESS_TOKEN_HEADER_NAME, jwtService.createAccessToken(requestDto));
        headers.add(REFRESH_TOKEN_HEADER_NAME, jwtService.createRefreshToken(requestDto));

        return ResponseEntity.ok().headers(headers).build();
    }

}
