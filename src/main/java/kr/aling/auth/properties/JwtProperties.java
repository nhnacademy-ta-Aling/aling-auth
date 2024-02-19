package kr.aling.auth.properties;

import java.time.Duration;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Jwt 관련 설정 Properties.
 *
 * @author 이수정
 * @since 1.0
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "aling.jwt")
public class JwtProperties {

    private String atkHeaderName;
    private String rtkHeaderName;

    private Duration atkExpireTime;
    private Duration rtkExpireTime;
}