package kr.aling.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.service.JwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@AutoConfigureRestDocs(outputDir = "target/snippets")
@WebMvcTest(JwtController.class)
class JwtControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("JWT 발급 성공")
    @WithMockUser
    void issueToken() throws Exception {
        // given
        String accessToken = "######";
        String refreshToken = "@@@@@@";

        IssueTokenRequestDto requestDto = new IssueTokenRequestDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        when(jwtService.createAccessToken(any())).thenReturn(accessToken);
        when(jwtService.createRefreshToken(any())).thenReturn(refreshToken);

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)));

        // then
        result.andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string(JwtController.ACCESS_TOKEN_HEADER_NAME, accessToken))
                .andExpect(header().string(JwtController.REFRESH_TOKEN_HEADER_NAME, refreshToken));

        // docs
        result.andDo(document("issue-token",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestFields(
                        fieldWithPath("userNo").type(JsonFieldType.NUMBER).description("회원 번호")
                                .attributes(key("valid").value("Not Null, 양수")),
                        fieldWithPath("roles").type(JsonFieldType.ARRAY).description("회원 권한")
                                .attributes(key("valid").value("Not Null"))
                )));
    }

    @Test
    @DisplayName("JWT 발급 실패 - 입력 데이터가 @Valid 검증 조건에 맞지 않은 경우")
    @WithMockUser
    void issueToken_invalidInput() throws Exception {
        // given
        IssueTokenRequestDto requestDto = new IssueTokenRequestDto(0L, null);

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/issue")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestDto)));

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest());
    }
}