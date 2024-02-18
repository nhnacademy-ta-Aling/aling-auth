package kr.aling.auth.service;

import kr.aling.auth.dto.request.TokenPayloadDto;

/**
 * JWT 발급 및 검증 Service interface.
 *
 * @author 이수정
 * @since 1.0
 */
public interface JwtService {

    /**
     * Access 토큰을 생성합니다. 유효 30분
     *
     * @param requestDto Access 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT AccessToken
     * @author 이수정
     * @since 1.0
     */
    String createAccessToken(TokenPayloadDto requestDto);

    /**
     * Refresh 토큰을 생성합니다. 유효 2주
     *
     * @param requestDto Refresh 토큰 생성에 필요한 정보를 담은 Dto.
     * @return 생성된 JWT RefreshToken
     * @author 이수정
     * @since 1.0
     */
    String createRefreshToken(TokenPayloadDto requestDto);

    /**
     * 토큰의 유효성을 검증하고 유효한 경우 회원의 식별 정보와 권한 정보를 반환합니다.
     *
     * @param token 검증할 JWT Token
     * @return 회원 식별 정보와 권한 정보
     * @author 이수정
     * @since 1.0
     */
    TokenPayloadDto verifyToken(String token);

    /**
     * Access 토큰을 재발급합니다.
     *
     * @param refreshToken 토큰 재발급을 위해 필요한 refresh 토큰
     * @return 재발급된 Access 토큰
     */
    String reissueToken(String refreshToken);
}
