package chanllenge.spring_security.authorization.architecture.method.manager;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.annotation.PostAuthorize;
import chanllenge.spring_security.authorization.architecture.method.expression.MethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.interceptor.MethodInvocationResult;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.lang.reflect.Method;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;

public final class PostAuthorizeAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {

    private MethodSecurityExpressionHandler expressionHandler;

    public PostAuthorizeAuthorizationManager(MethodSecurityExpressionHandler expressionHandler) {
        if (expressionHandler == null) {
            throw new IllegalArgumentException("MethodSecurityExpressionHandler는 null일 수 없습니다.");
        }
        this.expressionHandler = expressionHandler;
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, MethodInvocationResult invocationResult) {
        PostAuthorize postAuthorize = findPostAuthorize(invocationResult);
        if (postAuthorize == null) {
            return null;
        }

        boolean granted = evaluateExpression(
                postAuthorize.value(),
                authentication.get(),
                invocationResult.getMethodInvocation(),
                invocationResult.getResult()
        );
        return new CustomAuthorizationDecision(granted);
    }

    private boolean evaluateExpression(String expressionString, Authentication auth,
                                       MethodInvocation invocation, Object returnObject) {
        EvaluationContext ctx = expressionHandler.createEvaluationContext(auth, invocation);
        expressionHandler.setReturnObject(returnObject, ctx);
        Expression expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
        Boolean result = expression.getValue(ctx, Boolean.class);
        return Boolean.TRUE.equals(result);
    }

    private PostAuthorize findPostAuthorize(MethodInvocationResult invocationResult) {
        Method method = invocationResult.getMethodInvocation().getMethod();

        PostAuthorize postAuth = method.getAnnotation(PostAuthorize.class);
        if (postAuth != null) {
            return postAuth;
        }

        Class<?> targetClass = invocationResult.getMethodInvocation().getThis().getClass();
        return targetClass.getAnnotation(PostAuthorize.class);
    }

}
