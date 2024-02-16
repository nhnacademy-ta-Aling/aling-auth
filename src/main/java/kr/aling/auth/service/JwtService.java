package kr.aling.auth.service;

import kr.aling.auth.dto.request.IssueTokenRequestDto;

/**
 * JWT 발급 및 검증 Service interface.
 *
 * @author : 이수정
 * @since : 1.0
 */
public interface JwtService {

    /**
     * Access 토큰을 생성합니다.
     *
     * @param requestDto Access 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT AccessToken
     * @author : 이수정
     * @since : 1.0
     */
    String createAccessToken(IssueTokenRequestDto requestDto);

    /**
     * Refresh 토큰을 생성합니다.
     *
     * @param requestDto Refresh 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT RefreshToken
     * @author : 이수정
     * @since : 1.0
     */
    String createRefreshToken(IssueTokenRequestDto requestDto);
}
