package kr.aling.auth.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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

    private final JwtService jwtService;

    /**
     * 유저 번호와 권한을 받아 AccessToken, RefreshToken 헤더를 생성해 반환합니다.
     *
     * @param requestDto 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT 토큰을 헤더로 추가 후 응답
     * @author 이수정
     * @since 1.0
     */
    @PostMapping("/issue")
    public ResponseEntity<Void> issue(@Valid @RequestBody IssueTokenRequestDto requestDto) {
        return ResponseEntity.ok().headers(jwtService.issue(requestDto)).build();
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
        TokenPayloadDto payload = jwtService.getReissuePayload(request);
        return ResponseEntity.ok().headers(jwtService.reissue(payload)).build();
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
        jwtService.logout(userNo);
        return ResponseEntity.ok().build();
    }
}
