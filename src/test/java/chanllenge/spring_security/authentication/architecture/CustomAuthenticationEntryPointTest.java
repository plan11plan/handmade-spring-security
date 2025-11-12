package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.authentication.exception.AuthenticationException;
import chanllenge.spring_security.authentication.exception.UserNotFoundException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CustomAuthenticationEntryPointTest {

    private CustomAuthenticationEntryPoint entryPoint;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        entryPoint = new CustomAuthenticationEntryPoint();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        objectMapper = new ObjectMapper();
    }

    @DisplayName("인증 실패 발생 -> HTTP 응답 생성")
    @Test
    void commence_authenticationFailure_createsHttpResponse() throws Exception {
        // given
        AuthenticationException exception = new UserNotFoundException("User not found");

        // when
        entryPoint.commence(request, response, exception);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        Assertions.assertThat(response.getContentType()).isEqualTo("application/json;charset=UTF-8");
    }

    @DisplayName("예외 정보 -> 적절한 상태 코드와 메시지")
    @Test
    void commence_exception_returnsStatusCodeAndMessage() throws Exception {
        // given
        String exceptionMessage = "DB에 유저를 찾을 수 없습니다: 999";
        AuthenticationException exception = new UserNotFoundException(exceptionMessage);

        // when
        entryPoint.commence(request, response, exception);

        // then
        String jsonResponse = response.getContentAsString();
        Map<String, Object> responseMap = objectMapper.readValue(jsonResponse, Map.class);

        Assertions.assertThat(responseMap).containsKey("error");
        Assertions.assertThat(responseMap).containsKey("message");
        Assertions.assertThat(responseMap).containsKey("timestamp");

        Assertions.assertThat(responseMap.get("error")).isEqualTo("Unauthorized");
        Assertions.assertThat(responseMap.get("message")).isEqualTo(exceptionMessage);
    }
}
