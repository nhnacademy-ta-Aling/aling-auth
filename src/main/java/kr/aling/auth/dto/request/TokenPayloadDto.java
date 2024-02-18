package kr.aling.auth.dto.request;

import java.util.List;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * JWT 토큰에 포함하는 내용을 담는 Dto.
 *
 * @author 이수정
 * @since 1.0
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TokenPayloadDto {

    @NotNull
    @Positive
    private Long userNo;

    @NotNull
    private List<String> roles;
}
