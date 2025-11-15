package chanllenge.spring_security.authorization.architecture.method.interceptor;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.annotation.PreAuthorize;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.core.Ordered;

public final class AuthorizationManagerBeforeMethodInterceptor implements AuthorizationAdvisor {

    private final Pointcut pointcut;
    private final AuthorizationManager<MethodInvocation> authorizationManager;
    private int order = Ordered.HIGHEST_PRECEDENCE;

    public AuthorizationManagerBeforeMethodInterceptor(Pointcut pointcut, AuthorizationManager<MethodInvocation> authorizationManager) {
        if (pointcut == null) {
            throw new IllegalArgumentException("Pointcut은 Null일 수 없습니다.");
        }
        if (authorizationManager == null) {
            throw new IllegalArgumentException("AuthorizationManager는 null일 수 없습니다.");
        }

        this.pointcut = pointcut;
        this.authorizationManager = authorizationManager;
    }

    public static AuthorizationManagerBeforeMethodInterceptor preAuthorize(AuthorizationManager<MethodInvocation> authorizationManager) {
        Pointcut pointcut = new AnnotationMatchingPointcut(
                null,
                PreAuthorize.class,
                true
        );

        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, authorizationManager);
    }

    @Override
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        attemptAuthorization(methodInvocation);
        return methodInvocation.proceed();
    }

    private void attemptAuthorization(MethodInvocation methodInvocation) {
        Supplier<Authentication> authentication = this::getAuthentication;
        AuthorizationResult result = this.authorizationManager.authorize(authentication, methodInvocation);

        if (result != null && !result.isGranted()) {
            throw new AuthorizationDeniedException("접근이 거부되었습니다: " + methodInvocation.getMethod().getName(), result);
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
