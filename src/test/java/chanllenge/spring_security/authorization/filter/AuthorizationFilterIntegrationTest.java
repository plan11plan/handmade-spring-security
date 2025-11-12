package chanllenge.spring_security.authorization.filter;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
@DisplayName("권한 검사 통합 테스트")
class AuthorizationFilterIntegrationTest {

    private static final String BEARER_TOKEN_PREFIX = "Bearer user-";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    private static final String USER_PROTECTED_ENDPOINT = "/api/users/protected";
    private static final String ADMIN_USERS_ENDPOINT = "/api/admin/users";
    private static final String ADMIN_DASHBOARD_ENDPOINT = "/api/admin/dashboard";

    private static final String CONTENT_TYPE_JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    private User testUser;
    private User adminUser;

    @BeforeEach
    void setUp() {
        testUser = userRepository.save(new User("testuser", UserRole.USER));
        adminUser = userRepository.save(new User("adminuser", UserRole.ADMIN));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("권한 검사 통과")
    class AuthorizationGrantedTest {

        @Test
        @DisplayName("권한이 허용되면 다음 필터로 진행")
        void authorizedRequestProceedsToNextFilter() throws Exception {
            // given
            String validToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(USER_PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, validToken))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON));
        }

        @Test
        @DisplayName("ROLE_ADMIN이 admin 리소스 접근 시 허용")
        void adminRoleCanAccessAdminResource() throws Exception {
            // given
            String adminToken = BEARER_TOKEN_PREFIX + adminUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, adminToken))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON))
                    .andExpect(jsonPath("$.message").value("관리자만 접근 가능"));
        }

        @Test
        @DisplayName("ROLE_ADMIN이 admin 대시보드 접근 시 허용")
        void adminRoleCanAccessAdminDashboard() throws Exception {
            // given
            String adminToken = BEARER_TOKEN_PREFIX + adminUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_DASHBOARD_ENDPOINT).header(AUTHORIZATION_HEADER, adminToken))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON))
                    .andExpect(jsonPath("$.message").value("관리자 대시보드"));
        }
    }

    @Nested
    @DisplayName("권한 검사 실패 - 익명 사용자")
    class AuthorizationDeniedAnonymousTest {

        @Test
        @DisplayName("인증되지 않은 사용자는 AuthenticationEntryPoint 호출 - 401")
        void anonymousUserInvokesAuthenticationEntryPoint() throws Exception {
            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }

        @Test
        @DisplayName("토큰 없이 보호된 리소스 접근 시 401")
        void noTokenAccessProtectedResource() throws Exception {
            // expect
            mockMvc.perform(get(USER_PROTECTED_ENDPOINT))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }
    }

    @Nested
    @DisplayName("권한 검사 실패 - 인증된 사용자")
    class AuthorizationDeniedAuthenticatedTest {

        @Test
        @DisplayName("인증되었지만 권한이 없으면 AccessDeniedHandler 호출 - 403")
        void authenticatedButUnauthorizedInvokesAccessDeniedHandler() throws Exception {
            // given
            String userToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden())
                    .andExpect(content().contentTypeCompatibleWith("application/json"));
        }

        @Test
        @DisplayName("ROLE_USER가 ROLE_ADMIN 필요한 리소스 접근 시 거부 - 403")
        void userRoleCannotAccessAdminResource() throws Exception {
            // given
            String userToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_DASHBOARD_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden())
                    .andExpect(content().contentTypeCompatibleWith("application/json"));
        }

        @Test
        @DisplayName("ROLE_USER가 /api/admin/** 경로 접근 시 모두 거부")
        void userRoleCannotAccessAnyAdminEndpoint() throws Exception {
            // given
            String userToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden());
            mockMvc.perform(get(ADMIN_DASHBOARD_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("전체 권한 검사 통합 검증")
    class FullAuthorizationIntegrationTest {

        @Test
        @DisplayName("인증 성공 -> 권한 확인 -> 리소스 반환 전체 흐름")
        void successfulAuthenticationAndAuthorization() throws Exception {
            // given
            String adminToken = BEARER_TOKEN_PREFIX + adminUser.getId();

            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, adminToken))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON));
        }

        @Test
        @DisplayName("인증 실패 -> 권한 검사 전 401 반환")
        void authenticationFailureBeforeAuthorization() throws Exception {
            // given
            Long nonexistentUserId = 999L;
            String invalidToken = BEARER_TOKEN_PREFIX + nonexistentUserId;

            // expect
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, invalidToken))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().contentType(CONTENT_TYPE_JSON_UTF8));
        }

        @Test
        @DisplayName("인증 성공 -> 권한 실패 -> 403 반환")
        void authenticationSuccessButAuthorizationFailure() throws Exception {
            // given
            String userToken = BEARER_TOKEN_PREFIX + testUser.getId();

            // expect: 인증은 성공했으나 권한 부족으로 403
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden())
                    .andExpect(content().contentTypeCompatibleWith("application/json"));
        }

        @Test
        @DisplayName("다중 사용자 독립적인 권한 검사")
        void multipleUsersIndependentAuthorization() throws Exception {
            // given
            String userToken = BEARER_TOKEN_PREFIX + testUser.getId();
            String adminToken = BEARER_TOKEN_PREFIX + adminUser.getId();

            // expect1: USER는 user 리소스 접근 가능
            mockMvc.perform(get(USER_PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isOk());

            // expect2: USER는 admin 리소스 접근 불가
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, userToken))
                    .andExpect(status().isForbidden());

            // expect3: ADMIN은 admin 리소스 접근 가능
            mockMvc.perform(get(ADMIN_USERS_ENDPOINT).header(AUTHORIZATION_HEADER, adminToken))
                    .andExpect(status().isOk());

            // expect4: ADMIN은 user 리소스도 접근 가능
            mockMvc.perform(get(USER_PROTECTED_ENDPOINT).header(AUTHORIZATION_HEADER, adminToken))
                    .andExpect(status().isOk());
        }
    }
}
