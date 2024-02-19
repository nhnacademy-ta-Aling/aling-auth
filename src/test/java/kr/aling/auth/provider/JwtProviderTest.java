package kr.aling.auth.provider;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtProviderTest {

    private JwtProvider jwtProvider;

    @BeforeEach
    void setUp() {
        jwtProvider = new JwtProvider("secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretkk");
    }

    @Test
    @DisplayName("JWT 토큰 생성 성공")
    void createToken() {
        // given
        String userNo = "1";
        List<String> roles = List.of("ROLE_ADMIN", "ROLE_USER");
        long expireTime = 1000L;

        String encodedHeader = "eyJhbGciOiJIUzUxMiJ9.";
        String encodedPayload = "eyJzdWIiOiIxIiwicm9sZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfVVNFUiJd";

        // when
        String token = jwtProvider.createToken(userNo, roles, expireTime);

        // then
        assertTrue(token.startsWith(encodedHeader));
        assertTrue(token.split("\\.")[1].startsWith(encodedPayload));
    }

    @Test
    @DisplayName("JWT 토큰 파싱 실패 - 빈 문자열 토큰인 경우")
    void parseToken_blankToken() {
        // given
        String token = "";

        // when
        assertThatThrownBy(() -> jwtProvider.parseToken(token)).isInstanceOf(IllegalArgumentException.class);
    }
}