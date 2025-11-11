package chanllenge.spring_security.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;


@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration"
})
@AutoConfigureMockMvc
@Transactional
@DisplayName("인증 아키텍처 통합 테스트")
class SecurityIntegrationTest {

    private static final String BEARER_TOKEN_PREFIX = "Bearer user-";
    private static final String BASIC_AUTH_TOKEN = "Basic 1234";
    private static final Long NONEXISTENT_USER_ID = 999L;
    private static final String INVALID_TOKEN_FORMAT = "Bearer invalid-token-format";

    private static final String PROTECTED_ENDPOINT = "/api/users/protected";
    private static final String CURRENT_USER_ENDPOINT = "/api/users/me";

    private static final String CONTENT_TYPE_JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = userRepository.save(new User("testuser", UserRole.USER));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("필터 체인 구성 검증")
    class FilterChainConfigurationTest {

        @DisplayName("유효한 JWT 토큰이면 -> 인증 성공, 보호된 리소스 접근 ok")
        @Test
        void validToken_allowsAccess() throws Exception {
            // given
            String validToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, validToken))
                    .andExpect(status().isOk());
        }

        @DisplayName("유효한 JWT 토큰 -> SecurityContext에 인증 정보 저장")
        @Test
        void validToken_savesAuthenticationInContext() throws Exception {
            // given
            String validToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(CURRENT_USER_ENDPOINT).header(AUTHORIZATION_HEADER, validToken))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("인증 실패 흐름 검증")
    class AuthenticationFailureTest {

        @DisplayName("존재하지 않는 사용자 토큰 -> 401 응답")
        @Test
        void nonexistentUser_returns401() throws Exception {
            // given
            String invalidToken = BEARER_TOKEN_PREFIX + NONEXISTENT_USER_ID;

            // expect
            mockMvc.perform(get(PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, invalidToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }

        @DisplayName("잘못된 토큰 형식 -> 401 응답")
        @Test
        void invalidTokenFormat_returns401() throws Exception {
            // expect
            mockMvc.perform(get(PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, INVALID_TOKEN_FORMAT))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }
    }

    @Nested
    @DisplayName("인증 정보 없음 - 다음 필터로 전달")
    class NoAuthenticationTest {

        @DisplayName("Authorization 헤더 없음 -> 다음 필터로 전달 (200)")
        @Test
        void noAuthorizationHeader_passesThrough() throws Exception {
            // expect
            mockMvc.perform(get(PROTECTED_ENDPOINT))
                    .andExpect(status().isOk());
        }

        @DisplayName("Bearer 아닌 헤더 -> 다음 필터로 전달 (200)")
        @Test
        void nonBearerHeader_passesThrough() throws Exception {
            // expect
            mockMvc.perform(get(PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, BASIC_AUTH_TOKEN))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("전체 아키텍처 통합 검증")
    class FullArchitectureIntegrationTest {

        @DisplayName("인증 성공부터 리소스 반환까지")
        @Test
        void successfulAuthentication_returnsResource() throws Exception {
            // given
            String validToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect. 전체 흐름 검증
            // HTTP 요청 -> JwtAuthenticationFilter -> CustomProviderManager
            // -> CustomJwtAuthenticationProvider -> SecurityContext -> Controller
            mockMvc.perform(get(PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, validToken))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON));

            // SecurityContext에 인증 정보 확인
            mockMvc.perform(get(CURRENT_USER_ENDPOINT).header(AUTHORIZATION_HEADER, validToken))
                    .andExpect(status().isOk());
        }

        @DisplayName("인증 실패부터 에러 응답까지")
        @Test
        void failedAuthentication_returnsError() throws Exception {
            // given
            String invalidToken = BEARER_TOKEN_PREFIX + NONEXISTENT_USER_ID;

            // expect. 전체 실패 흐름 검증
            // HTTP 요청 -> JwtAuthenticationFilter -> CustomProviderManager -> CustomJwtAuthenticationProvider (예외 발생)
            // -> CustomAuthenticationEntryPoint -> 401 JSON 응답
            mockMvc.perform(get(PROTECTED_ENDPOINT)
                            .header(AUTHORIZATION_HEADER, invalidToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }

        @DisplayName("다중 요청 - 각 요청마다 독립적인 SecurityContext")
        @Test
        void multipleRequests_independentSecurityContext() throws Exception {
            // given
            User user1 = userRepository.save(new User("user1", UserRole.USER));
            User user2 = userRepository.save(new User("user2", UserRole.USER));

            String token1 = BEARER_TOKEN_PREFIX + user1.getId();
            String token2 = BEARER_TOKEN_PREFIX + user2.getId();

            // expect1: 첫 번째 요청
            mockMvc.perform(get(CURRENT_USER_ENDPOINT).header(AUTHORIZATION_HEADER, token1))
                    .andExpect(status().isOk());

            // expect2: 두 번째 요청 (독립적인 SecurityContext) 확인
            mockMvc.perform(get(CURRENT_USER_ENDPOINT).header(AUTHORIZATION_HEADER, token2))
                    .andExpect(status().isOk());
        }
    }
}
