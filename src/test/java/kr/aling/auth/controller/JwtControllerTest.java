package kr.aling.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import kr.aling.auth.dto.TokenPayloadDto;
import kr.aling.auth.dto.request.IssueTokenRequestDto;
import kr.aling.auth.service.JwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
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
    void issue() throws Exception {
        // given
        String accessToken = "######";
        String refreshToken = "@@@@@@";

        IssueTokenRequestDto requestDto = new IssueTokenRequestDto(1L, List.of("ROLE_ADMIN", "ROLE_USER"));

        HttpHeaders headers = new HttpHeaders();
        headers.add("ACCESS_TOKEN", accessToken);
        headers.add("REFRESH_TOKEN", refreshToken);
        when(jwtService.issue(any())).thenReturn(headers);

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)));

        // then
        result.andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("ACCESS_TOKEN", accessToken))
                .andExpect(header().string("REFRESH_TOKEN", refreshToken));

        // docs
        result.andDo(document("issue-token",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestFields(
                        fieldWithPath("userNo").type(JsonFieldType.NUMBER).description("회원 번호")
                                .attributes(key("valid").value("Not Null, 양수")),
                        fieldWithPath("roles").type(JsonFieldType.ARRAY).description("회원 권한")
                                .attributes(key("valid").value("Not Null"))
                ),
                responseHeaders(
                        headerWithName("ACCESS_TOKEN").description("발급된 Access Token"),
                        headerWithName("REFRESH_TOKEN").description("발급된 Refresh Token")
                )));
    }

    @Test
    @DisplayName("JWT 발급 실패 - 입력 데이터가 @Valid 검증 조건에 맞지 않은 경우")
    @WithMockUser
    void issue_invalidInput() throws Exception {
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

    @Test
    @DisplayName("JWT 재발급 성공")
    @WithMockUser
    void reissue() throws Exception {
        // given
        String accessToken = "######";
        TokenPayloadDto tokenPayloadDto = new TokenPayloadDto("1", List.of("ROLE_ADMIN", "ROLE_USER"));
        when(jwtService.getReissuePayload(any())).thenReturn(tokenPayloadDto);

        HttpHeaders headers = new HttpHeaders();
        headers.add("ACCESS_TOKEN", accessToken);
        when(jwtService.reissue(tokenPayloadDto)).thenReturn(headers);

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/reissue")
                .header("REFRESH_TOKEN", "refresh"));

        // then
        result.andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("ACCESS_TOKEN", accessToken));

        // docs
        result.andDo(document("reissue-token",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("REFRESH_TOKEN").description("토큰 재발급을 위한 Refresh Token")
                ),
                responseHeaders(
                        headerWithName("ACCESS_TOKEN").description("재발급된 Access Token")
                )));
    }

    @Test
    @DisplayName("JWT 재발급 실패 - Refresh Token을 담은 헤더가 존재하지 않는 경우")
    @WithMockUser
    void reissue_refreshTokenHeaderNotExists() throws Exception {
        // given
        when(jwtService.getReissuePayload(any())).thenThrow(IllegalArgumentException.class);

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/reissue"));

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("로그아웃 처리 성공")
    @WithMockUser
    void logout() throws Exception {
        // given
        long userNo = 1L;

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/logout")
                .param("userNo", Long.toString(userNo)));

        // then
        result.andDo(print())
                .andExpect(status().isOk());

        // docs
        result.andDo(document("logout",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestParameters(
                        parameterWithName("userNo").description("로그아웃하는 회원의 번호")
                                .attributes(key("valid").value("Not Null, 양수"))
                )));
    }

    @Test
    @DisplayName("로그아웃 처리 실패 - 입력 데이터가 @Valid 검증 조건에 맞지 않은 경우")
    @WithMockUser
    void logout_invalidInput() throws Exception {
        // given
        long userNo = 0L;

        // when
        ResultActions result = mockMvc.perform(get("/api/v1/jwt/logout")
                .param("userNo", Long.toString(userNo)));

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest());
    }
}