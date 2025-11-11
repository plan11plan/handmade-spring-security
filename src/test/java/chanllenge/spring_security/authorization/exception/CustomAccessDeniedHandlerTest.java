package chanllenge.spring_security.authorization.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class CustomAccessDeniedHandlerTest {

    private CustomAccessDeniedHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        handler = new CustomAccessDeniedHandler(objectMapper);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("권한 거부 시 예외를 처리한다.")
    void handle_access_denied_exception_returns_403() throws Exception {
        // given
        AuthorizationDeniedException exception = new AuthorizationDeniedException("권한이 없습니다");

        // when
        handler.handle(request, response, exception);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }
}
