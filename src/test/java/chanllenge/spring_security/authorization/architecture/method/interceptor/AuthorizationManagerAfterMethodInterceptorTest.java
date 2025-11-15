package chanllenge.spring_security.authorization.architecture.method.interceptor;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authentication.context.SecurityContext;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class AuthorizationManagerAfterMethodInterceptorTest {

    private AuthorizationManager<MethodInvocationResult> authorizationManager;
    private AuthorizationManagerAfterMethodInterceptor interceptor;
    private MethodInvocation methodInvocation;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        authorizationManager = Mockito.mock(AuthorizationManager.class);
        interceptor = AuthorizationManagerAfterMethodInterceptor.postAuthorize(authorizationManager);
        methodInvocation = Mockito.mock(MethodInvocation.class);

        Mockito.when(methodInvocation.getMethod()).thenReturn(
                Object.class.getMethod("toString")
        );

        Authentication authentication = createAuthentication(true, "ROLE_USER");
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @DisplayName("메서드를 먼저 실행하여 반환값 획득")
    @Test
    void invoke_executesMethodFirst() throws Throwable {
        // given
        String expectedResult = "method-result";
        Mockito.when(methodInvocation.proceed()).thenReturn(expectedResult);
        Mockito.when(authorizationManager.authorize(Mockito.any(Supplier.class), Mockito.any(MethodInvocationResult.class)))
                .thenReturn(new CustomAuthorizationDecision(true));

        // when
        Object result = interceptor.invoke(methodInvocation);

        // then
        Mockito.verify(methodInvocation).proceed();
        Assertions.assertThat(result).isEqualTo(expectedResult);
    }

    @DisplayName("권한이 있으면 반환값 반환")
    @Test
    void invoke_granted_returnsResult() throws Throwable {
        // given
        String expectedResult = "method-result";
        Mockito.when(methodInvocation.proceed()).thenReturn(expectedResult);
        Mockito.when(authorizationManager.authorize(Mockito.any(Supplier.class), Mockito.any(MethodInvocationResult.class)))
                .thenReturn(new CustomAuthorizationDecision(true));

        // when
        Object result = interceptor.invoke(methodInvocation);

        // then
        Assertions.assertThat(result).isEqualTo(expectedResult);
    }

    @DisplayName("권한이 없으면 AuthorizationDeniedException 발생")
    @Test
    void invoke_denied_throwsExceptionAfterMethodExecution() throws Throwable {
        // given
        Mockito.when(methodInvocation.proceed()).thenReturn("some-result");
        Mockito.when(authorizationManager.authorize(Mockito.any(Supplier.class), Mockito.any(MethodInvocationResult.class)))
                .thenReturn(new CustomAuthorizationDecision(false));

        // expect
        Assertions.assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOf(AuthorizationDeniedException.class);
        Mockito.verify(methodInvocation).proceed();
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
}
