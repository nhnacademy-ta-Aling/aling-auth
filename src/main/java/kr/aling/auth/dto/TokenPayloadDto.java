package kr.aling.auth.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * JWT 토큰 내 정보를 담는 Dto.
 *
 * @author 이수정
 * @since 1.0
 */
@Getter
@AllArgsConstructor
public class TokenPayloadDto {

    private final String userNo;
    private final List<String> roles;
}
