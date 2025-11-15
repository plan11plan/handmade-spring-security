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

class AuthorizationManagerBeforeMethodInterceptorTest {

    private AuthorizationManager<MethodInvocation> authorizationManager;
    private AuthorizationManagerBeforeMethodInterceptor interceptor;
    private MethodInvocation methodInvocation;

    @BeforeEach
    void setUp() throws Exception {
        authorizationManager = Mockito.mock(AuthorizationManager.class);
        interceptor = AuthorizationManagerBeforeMethodInterceptor.preAuthorize(authorizationManager);
        methodInvocation = Mockito.mock(MethodInvocation.class);

        Mockito.when(methodInvocation.getMethod()).thenReturn(Object.class.getMethod("toString"));

        Authentication authentication = createAuthentication(true, "ROLE_USER");
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @DisplayName("권한이 있으면 메서드 실행")
    @Test
    void invoke_granted_proceedsToMethod() throws Throwable {
        // given
        Mockito.when(authorizationManager.authorize(Mockito.any(Supplier.class), Mockito.any(MethodInvocation.class)))
                .thenReturn(new CustomAuthorizationDecision(true));
        Mockito.when(methodInvocation.proceed()).thenReturn("method-result");

        // when
        Object result = interceptor.invoke(methodInvocation);

        // then
        Assertions.assertThat(result).isEqualTo("method-result");
        Mockito.verify(methodInvocation).proceed();
    }

    @DisplayName("권한이 없으면 AuthorizationDeniedException 발생")
    @Test
    void invoke_denied_throwsException() throws Throwable {
        // given
        Mockito.when(authorizationManager.authorize(Mockito.any(Supplier.class), Mockito.any(MethodInvocation.class)))
                .thenReturn(new CustomAuthorizationDecision(false));

        // expect
        Assertions.assertThatThrownBy(() -> interceptor.invoke(methodInvocation))
                .isInstanceOf(AuthorizationDeniedException.class);
        Mockito.verify(methodInvocation, Mockito.never()).proceed();
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
