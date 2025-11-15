package chanllenge.spring_security.authorization.architecture.method.manager;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.annotation.PreAuthorize;
import chanllenge.spring_security.authorization.architecture.method.expression.MethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.lang.reflect.Method;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;

public final class PreAuthorizeAuthorizationManager implements AuthorizationManager<MethodInvocation> {

    private MethodSecurityExpressionHandler expressionHandler;

    public PreAuthorizeAuthorizationManager(MethodSecurityExpressionHandler expressionHandler) {
        if (expressionHandler == null) {
            throw new IllegalArgumentException("MethodSecurityExpressionHandler는 null일 수 없습니다.");
        }
        this.expressionHandler = expressionHandler;
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, MethodInvocation invocation) {
        PreAuthorize preAuthorize = findPreAuthorize(invocation);
        if (preAuthorize == null) {
            return null;
        }

        boolean granted = evaluateExpression(preAuthorize.value(), authentication.get(), invocation);
        return new CustomAuthorizationDecision(granted);
    }

    private boolean evaluateExpression(String expressionString, Authentication auth, MethodInvocation invocation) {
        EvaluationContext ctx = expressionHandler.createEvaluationContext(auth, invocation);
        Expression expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
        Boolean result = expression.getValue(ctx, Boolean.class);
        return Boolean.TRUE.equals(result);
    }

    private PreAuthorize findPreAuthorize(MethodInvocation mi) {
        Method method = mi.getMethod();
        PreAuthorize preAuth = method.getAnnotation(PreAuthorize.class);
        if (preAuth != null) {
            return preAuth;
        }

        Class<?> targetClass = mi.getThis().getClass();
        return targetClass.getAnnotation(PreAuthorize.class);
    }
}
