package kr.aling.auth.jwt;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtProviderTest {

    private JwtProvider jwtProvider;

    @BeforeEach
    void setUp() {
        jwtProvider = new JwtProvider(
                "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretkk");
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
}