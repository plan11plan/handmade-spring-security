package chanllenge.spring_security.authorization.architecture.method.manager;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authorization.architecture.method.annotation.PostAuthorize;
import chanllenge.spring_security.authorization.architecture.method.expression.DefaultMethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.expression.MethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.interceptor.MethodInvocationResult;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class PostAuthorizeAuthorizationManagerTest {

    private MethodSecurityExpressionHandler expressionHandler;
    private PostAuthorizeAuthorizationManager manager;
    private Authentication userAuthentication;

    @BeforeEach
    void setUp() {
        expressionHandler = new DefaultMethodSecurityExpressionHandler();
        manager = new PostAuthorizeAuthorizationManager(expressionHandler);
        userAuthentication = createAuthentication(true, "ROLE_USER");
    }

    @DisplayName("정상적인 ExpressionHandler로 생성 성공")
    @Test
    void createWithValidHandler() {
        // given
        MethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();

        // expect
        Assertions.assertThatCode(() -> new PostAuthorizeAuthorizationManager(handler))
                .doesNotThrowAnyException();
    }

    @DisplayName("null ExpressionHandler로 생성 시 예외 발생")
    @Test
    void createWithNullHandler_exception() {
        // expect
        Assertions.assertThatThrownBy(() -> new PostAuthorizeAuthorizationManager(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @DisplayName("표현식 평가 결과가 true이면 granted 반환")
    @Test
    void authorize_expressionTrue_then_true() throws Exception {
        // given
        String returnValue = "test";
        MethodInvocationResult invocationResult = createMethodInvocationResult(
                "methodWithPostAuthorize", returnValue
        );

        // when
        AuthorizationResult result = manager.authorize(() -> userAuthentication, invocationResult);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    @DisplayName("표현식 평가 결과가 false이면 false 반환")
    @Test
    void authorize_expressionFalse_then_false() throws Exception {
        // given
        MethodInvocationResult invocationResult = createMethodInvocationResult(
                "methodWithPostAuthorize",
                null
        );

        // when
        AuthorizationResult result = manager.authorize(() -> userAuthentication, invocationResult);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isGranted()).isFalse();
    }

    @DisplayName("returnObject 속성 접근 표현식 평가")
    @Test
    void authorize_returnObject() throws Exception {
        // given
        TestUser returnValue = new TestUser(1L, "testuser");
        MethodInvocationResult invocationResult = createMethodInvocationResult(
                "methodWithReturnObject", returnValue
        );

        // when
        AuthorizationResult result = manager.authorize(() -> userAuthentication, invocationResult);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    private MethodInvocationResult createMethodInvocationResult(String methodName, Object returnValue) throws Exception {

        MethodInvocation invocation = Mockito.mock(MethodInvocation.class);
        TestService target = new TestService();
        Method method = TestService.class.getMethod(methodName);

        Mockito.when(invocation.getMethod()).thenReturn(method);
        Mockito.when(invocation.getThis()).thenReturn(target);
        Mockito.when(invocation.getArguments()).thenReturn(new Object[0]);

        return new MethodInvocationResult(invocation, returnValue);
    }

    private Authentication createAuthentication(boolean authenticated, String... authorities) {
        return new Authentication() {
            @Override
            public String getName() {
                return "test-user";
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return List.of(authorities).stream()
                        .map(auth -> (GrantedAuthority) () -> auth)
                        .toList();
            }

            @Override
            public Object getPrincipal() {
                return 1L;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return authenticated;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            }
        };
    }

    // Test classes

    class TestService {

        @PostAuthorize("returnObject != null")
        public Object methodWithPostAuthorize() {
            return null;
        }

        @PostAuthorize("returnObject.id == 1")
        public Object methodWithReturnObject() {
            return null;
        }
    }

    class TestUser {
        private final Long id;
        private final String username;

        public TestUser(Long id, String username) {
            this.id = id;
            this.username = username;
        }

        public Long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }
    }
}
