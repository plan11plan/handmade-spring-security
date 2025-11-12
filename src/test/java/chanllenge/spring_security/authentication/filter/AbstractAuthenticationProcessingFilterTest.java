package chanllenge.spring_security.authentication.filter;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import chanllenge.spring_security.authentication.architecture.CustomAuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.CustomJwtAuthenticationProvider;
import chanllenge.spring_security.authentication.architecture.CustomProviderManager;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class AbstractAuthenticationProcessingFilterTest {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserRepository userRepository;

    private JwtAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;
    private CustomProviderManager providerManager;
    private CustomAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        CustomJwtAuthenticationProvider provider =
                new CustomJwtAuthenticationProvider(userDetailsService);
        providerManager = new CustomProviderManager(List.of(provider));
        entryPoint = new CustomAuthenticationEntryPoint();

        filter = new JwtAuthenticationFilter(providerManager, entryPoint);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = mock(FilterChain.class);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @DisplayName("HTTP 요청에서 인증을 시도한다.")
    @Nested
    class TryAtHttpRequest{
        @DisplayName("인증 필요한 요청 -> 인증 시도")
        @Test
        void attemptAuthentication () throws Exception {
            // given
            User user = userRepository.save(new User("testuser", UserRole.USER));
            request.addHeader("Authorization", "Bearer user-" + user.getId());

            // when
            filter.doFilter(request, response, filterChain);

            // then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Assertions.assertThat(auth).isNotNull();
            Assertions.assertThat(auth.isAuthenticated()).isTrue();
            verify(filterChain, times(1)).doFilter(request, response);
        }

        @DisplayName("인증 성공 -> 다음 처리로 진행")
        @Test
        void attemptAuthentication_proceedsToNextFilter () throws Exception {
        // given
        User user = userRepository.save(new User("testuser", UserRole.USER));
        request.addHeader("Authorization", "Bearer user-" + user.getId());

        // when
        filter.doFilter(request, response, filterChain);

        // then
        verify(filterChain, times(1)).doFilter(request, response);
    }

        @DisplayName("인증 실패 -> 실패 응답 생성")
        @Test
        void attemptAuthentication_createsErrorResponse () throws Exception {
        // given
        Long nonexistentUserId = 999L;
        request.addHeader("Authorization", "Bearer user-" + nonexistentUserId);

        // when
        filter.doFilter(request, response, filterChain);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(401);
        Assertions.assertThat(response.getContentType()).contains("application/json");
        verify(filterChain, never()).doFilter(request, response);
    }
    }


    @DisplayName("요청에서 인증 정보를 추출한다.")
    @Nested
    class ExtractAuthenticationAtRequest {

        @DisplayName("HTTP 요청 -> 인증 정보 생성")
        @Test
        void attemptAuthentication_attemptAuthentication() throws Exception {
            // given
            User user = userRepository.save(new User("testuser", UserRole.USER));
            request.addHeader("Authorization", "Bearer user-" + user.getId());

            // when
            filter.doFilter(request, response, filterChain);

            // then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Assertions.assertThat(auth).isNotNull();
        }

        @DisplayName("인증 정보 없음 -> null 반환")
        @Test
        void attemptAuthentication_noAuthInfo_returnsNull() throws Exception {
            // given
            // Authorization 헤더 없음

            // when
            filter.doFilter(request, response, filterChain);

            // then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Assertions.assertThat(auth).isNull();
            verify(filterChain, times(1)).doFilter(request, response);
        }
    }


    @DisplayName("인증 결과를 처리한다.")
    @Nested
    class ProcessAuthenticationResult {
        @DisplayName("인증 성공 -> 보안 컨텍스트에 저장")
        @Test
        void attemptAuthentication_savesToSecurityContext() throws Exception {
            // given
            User user = userRepository.save(new User("testuser", UserRole.USER));
            request.addHeader("Authorization", "Bearer user-" + user.getId());

            // when
            filter.doFilter(request, response, filterChain);

            // then
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Assertions.assertThat(auth).isNotNull();
            Assertions.assertThat(auth.isAuthenticated()).isTrue();
        }

        @DisplayName("인증 실패 -> 실패 핸들러 호출")
        @Test
        void attemptAuthentication_call_EntryPoint() throws Exception {
            // given
            Long nonexistentUserId = 999L;
            request.addHeader("Authorization", "Bearer user-" + nonexistentUserId);

            // when
            filter.doFilter(request, response, filterChain);

            // then
            Assertions.assertThat(response.getStatus()).isEqualTo(401);
            String jsonResponse = response.getContentAsString();
            Assertions.assertThat(jsonResponse).contains("Unauthorized");
        }
    }
}
