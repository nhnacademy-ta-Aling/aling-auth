package kr.aling.auth.service;

import javax.servlet.http.HttpServletRequest;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import org.springframework.http.HttpHeaders;

/**
 * JWT 발급 및 검증 Service interface.
 *
 * @author 이수정
 * @since 1.0
 */
public interface JwtService {

    /**
     * AccessToken과 RefreshToken을 생성해 header로 반환합니다.
     *
     * @param requestDto 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 AccessToken과 RefreshToken을 포함하는 HttpHeaders
     * @author 이수정
     * @since 1.0
     */
    HttpHeaders issue(IssueTokenRequestDto requestDto);

    /**
     * RefreshToken을 파싱하여 유효성을 검사하고 AccessToken을 생성하기 위한 정보를 반환합니다.
     *
     * @param request 요청의 헤더를 얻기 위한 HttpServletRequest 객체
     * @return AccessToken을 생성하기 위한 정보
     * @author 이수정
     * @since 1.0
     */
    TokenPayloadDto getReissuePayload(HttpServletRequest request);

    /**
     * AccessToken을 재발급합니다.
     *
     * @param payloadDto 재발급에 필요한 정보를 담은 Dto.
     * @return 생성된 AccessToken을 담은 HttpHeaders
     * @author 이수정
     * @since 1.0
     */
    HttpHeaders reissue(TokenPayloadDto payloadDto);

    /**
     * 로그아웃 시 RefreshToken을 만료시킵니다.
     *
     * @param userNo RefreshToken 만료시킬 유저번호
     * @author 이수정
     * @since 1.0
     */
    void logout(Long userNo);
}
