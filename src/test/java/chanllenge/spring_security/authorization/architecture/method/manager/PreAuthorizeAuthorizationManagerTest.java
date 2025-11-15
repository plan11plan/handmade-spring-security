package chanllenge.spring_security.authorization.architecture.method.manager;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authorization.architecture.method.annotation.PreAuthorize;
import chanllenge.spring_security.authorization.architecture.method.expression.DefaultMethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.expression.MethodSecurityExpressionHandler;
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

class PreAuthorizeAuthorizationManagerTest {

    private MethodSecurityExpressionHandler expressionHandler;
    private PreAuthorizeAuthorizationManager manager;
    private Authentication adminAuthentication;

    @BeforeEach
    void setUp() {
        expressionHandler = new DefaultMethodSecurityExpressionHandler();
        manager = new PreAuthorizeAuthorizationManager(expressionHandler);
        adminAuthentication = createAuthentication(true, "ROLE_ADMIN");
    }

    @DisplayName("정상적인 ExpressionHandler로 생성 성공")
    @Test
    void createWithValidHandler() {
        // given
        MethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();

        // expect
        Assertions.assertThatCode(() -> new PreAuthorizeAuthorizationManager(handler))
                .doesNotThrowAnyException();
    }

    @DisplayName("null ExpressionHandler로 생성 시 예외 발생")
    @Test
    void createWithNullHandler_exception() {
        // expect
        Assertions.assertThatThrownBy(() -> new PreAuthorizeAuthorizationManager(null))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("표현식 평가 결과가 true이면 true 반환")
    @Test
    void authorize_expressionTrue_then_true() throws Exception {
        // given
        MethodInvocation invocation = createMethodInvocation("hasRoleAdmin", "hasRole('ADMIN')");

        // when
        AuthorizationResult result = manager.authorize(() -> adminAuthentication, invocation);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    @DisplayName("표현식 평가 결과가 false이면 false 반환")
    @Test
    void authorize_expressionFalse_then_false() throws Exception {
        // given

        MethodInvocation invocation = createMethodInvocation("hasRoleA", "hasRole('A')");

        // when
        AuthorizationResult result = manager.authorize(() -> adminAuthentication, invocation);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isGranted()).isFalse();
    }

    private MethodInvocation createMethodInvocation(String methodName, String preAuthorizeValue) throws Exception {
        MethodInvocation invocation = Mockito.mock(MethodInvocation.class);
        TestService target = new TestService();
        Method method = TestService.class.getMethod(methodName);

        Mockito.when(invocation.getMethod()).thenReturn(method);
        Mockito.when(invocation.getThis()).thenReturn(target);
        Mockito.when(invocation.getArguments()).thenReturn(new Object[0]);

        return invocation;
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
                return "test-user";
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

    class TestService {

        @PreAuthorize("hasRole('ADMIN')")
        public void hasRoleAdmin() {
        }

        @PreAuthorize("hasRole('A')")
        public void hasRoleA() {
        }
    }
}
