package chanllenge.spring_security.authorization.architecture.method.interceptor;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.annotation.PostAuthorize;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.core.Ordered;

public final class AuthorizationManagerAfterMethodInterceptor implements AuthorizationAdvisor {

    private final Pointcut pointcut;
    private final AuthorizationManager<MethodInvocationResult> authorizationManager;
    private int order = Ordered.LOWEST_PRECEDENCE;

    public AuthorizationManagerAfterMethodInterceptor(Pointcut pointcut, AuthorizationManager<MethodInvocationResult> authorizationManager) {
        if (pointcut == null) {
            throw new IllegalArgumentException("Pointcut은 Null일 수 없습니다.");
        }
        if (authorizationManager == null) {
            throw new IllegalArgumentException("AuthorizationManager는 null일 수 없습니다.");
        }

        this.pointcut = pointcut;
        this.authorizationManager = authorizationManager;
    }

    public static AuthorizationManagerAfterMethodInterceptor postAuthorize(AuthorizationManager<MethodInvocationResult> authorizationManager) {
        Pointcut pointcut = new AnnotationMatchingPointcut(
                null,
                PostAuthorize.class,
                true
        );

        return new AuthorizationManagerAfterMethodInterceptor(pointcut, authorizationManager);
    }

    @Override
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        Object returnedObject = methodInvocation.proceed();
        attemptAuthorization(methodInvocation, returnedObject);
        return returnedObject;
    }

    private void attemptAuthorization(MethodInvocation methodInvocation, Object returnedObject) {
        MethodInvocationResult invocationResult = new MethodInvocationResult(methodInvocation, returnedObject);
        Supplier<Authentication> authentication = this::getAuthentication;
        AuthorizationResult result = this.authorizationManager.authorize(authentication, invocationResult);

        if (result != null && !result.isGranted()) {
            throw new AuthorizationDeniedException("접근이 거부되었습니다: " + methodInvocation.getMethod().getName(), result
            );
        }
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Override
    public Pointcut getPointcut() {
        return this.pointcut;
    }

    @Override
    public int getOrder() {
        return this.order;
    }
}
