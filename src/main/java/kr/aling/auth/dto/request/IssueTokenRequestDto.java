package kr.aling.auth.dto.request;

import java.util.List;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * JWT AccessToken, RefreshToken 생성 요청 파라미터를 담는 Dto.
 *
 * @author 이수정
 * @since 1.0
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class IssueTokenRequestDto {

    @NotNull
    @Positive
    private Long userNo;

    @NotEmpty
    private List<String> roles;
}
