package kr.aling.auth.jwt;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
    }


    @Test
    @DisplayName("JWT 토큰 파싱 실패 - 빈 문자열 토큰인 경우")
    void parseToken_blankToken() {
        // given
        String secretKey = "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretkk";
        String token = "";

        // when
        assertThatThrownBy(() -> jwtUtils.parseToken(secretKey, token)).isInstanceOf(IllegalArgumentException.class);
    }
}