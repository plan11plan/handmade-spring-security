package chanllenge.spring_security.authorization.architecture.method.expression;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Collection;
import java.util.List;
import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;

class DefaultMethodSecurityExpressionHandlerTest {

    private DefaultMethodSecurityExpressionHandler handler;
    private Authentication authentication;
    private MethodInvocation methodInvocation;

    @BeforeEach
    void setUp() throws Exception {
        handler = new DefaultMethodSecurityExpressionHandler();
        authentication = createAuthentication(true, "ROLE_ADMIN");

        methodInvocation = Mockito.mock(MethodInvocation.class);
        Mockito.when(methodInvocation.getThis()).thenReturn(new Object());
        Mockito.when(methodInvocation.getMethod()).thenReturn(Object.class.getMethod("toString"));
    }

    @DisplayName("getExpressionParser() -> SpelExpressionParser 반환")
    @Test
    void getExpressionParser_returnsSpelExpressionParser() {
        // when
        var parser = handler.getExpressionParser();

        // then
        Assertions.assertThat(parser).isNotNull();
        Assertions.assertThat(parser.getClass().getSimpleName()).isEqualTo("SpelExpressionParser");
    }

    @DisplayName("createEvaluationContext() -> StandardEvaluationContext 반환")
    @Test
    void createEvaluationContext_returnsStandardEvaluationContext() {
        // when
        EvaluationContext ctx = handler.createEvaluationContext(authentication, methodInvocation);

        // then
        Assertions.assertThat(ctx).isNotNull();
        Assertions.assertThat(ctx.getClass().getSimpleName()).isEqualTo("StandardEvaluationContext");
    }

    @DisplayName("createEvaluationContext() -> MethodSecurityExpressionRoot를 root로 설정")
    @Test
    void createEvaluationContext_setsMethodSecurityExpressionRootAsRoot() {
        // when
        EvaluationContext ctx = handler.createEvaluationContext(authentication, methodInvocation);

        // then
        Assertions.assertThat(ctx.getRootObject()).isNotNull();
        Assertions.assertThat(ctx.getRootObject().getValue()).isInstanceOf(MethodSecurityExpressionRoot.class);

        MethodSecurityExpressionRoot root = (MethodSecurityExpressionRoot) ctx.getRootObject().getValue();
        Assertions.assertThat(root.getAuthentication()).isEqualTo(authentication);
        Assertions.assertThat(root.getTarget()).isEqualTo(methodInvocation.getThis());
    }

    @DisplayName("setReturnObject() -> root의 returnObject 설정")
    @Test
    void setReturnObject_setsReturnObjectInRoot() {
        // given
        EvaluationContext ctx = handler.createEvaluationContext(authentication, methodInvocation);
        String returnValue = "test";

        // when
        handler.setReturnObject(returnValue, ctx);

        // then
        MethodSecurityExpressionRoot root = (MethodSecurityExpressionRoot) ctx.getRootObject().getValue();
        Assertions.assertThat(root.getReturnObject()).isEqualTo(returnValue);
    }

    @DisplayName("rootObject가 MethodSecurityExpressionRoot가 아니면 IllegalStateException")
    @Test
    void setReturnObject_wrongRootType_throwsIllegalStateException() {
        // given
        EvaluationContext ctx = Mockito.mock(EvaluationContext.class);
        org.springframework.expression.TypedValue typedValue = Mockito.mock(org.springframework.expression.TypedValue.class);

        Mockito.when(ctx.getRootObject()).thenReturn(typedValue);
        Mockito.when(typedValue.getValue()).thenReturn("aa");

        // expect
        Assertions.assertThatThrownBy(() -> handler.setReturnObject("test", ctx)).isInstanceOf(IllegalStateException.class);
    }

    @DisplayName("filter() -> 예외")
    @Test
    void filter_exception() {
        // given
        EvaluationContext ctx = handler.createEvaluationContext(authentication, methodInvocation);
        Expression expression = handler.getExpressionParser().parseExpression("true");

        // expect
        Assertions.assertThatThrownBy(() -> handler.filter(List.of("a1", "aa"), expression, ctx))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    // Helper methods

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
