package kr.aling.auth.dto.request;

import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * JWT 발급 요청 파라미터를 담는 Dto.
 *
 * @author : 이수정
 * @since : 1.0
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class IssueTokenRequestDto {

    private Long userNo;
    private List<String> role;
}
