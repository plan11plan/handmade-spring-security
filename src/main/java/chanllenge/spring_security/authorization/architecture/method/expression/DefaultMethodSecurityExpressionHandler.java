package chanllenge.spring_security.authorization.architecture.method.expression;

import chanllenge.spring_security.authentication.context.Authentication;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public final class DefaultMethodSecurityExpressionHandler implements MethodSecurityExpressionHandler {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    @Override
    public ExpressionParser getExpressionParser() {
        return this.parser;
    }

    /**
     * EvaluationContext 구현으로 MethodSecurityEvaluationContext 를 사용한다.
     */
    @Override
    public EvaluationContext createEvaluationContext(Authentication authentication, MethodInvocation mi) {
        MethodSecurityExpressionRoot root = createSecurityExpressionRoot(authentication,mi);
        StandardEvaluationContext context = new StandardEvaluationContext(root);
        return context;
    }

    private MethodSecurityExpressionRoot createSecurityExpressionRoot(Authentication authentication, MethodInvocation mi) {
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(authentication);
        root.setTarget(mi.getThis());
        return root;
    }

    /**
     * 메서드 필터 구현 안해서 사용 안함.
     */
    @Override
    public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
        throw new UnsupportedOperationException("메서드 인가 filter는 현재 구현되지 않았습니다.");
    }

    @Override
    public void setReturnObject(Object returnObject, EvaluationContext ctx) {
        Object rootObject = ctx.getRootObject().getValue();

        if (rootObject instanceof MethodSecurityExpressionRoot root) {
            root.setReturnObject(returnObject);
        } else {
            throw new IllegalStateException(
                    "EvaluationContext의 rootObject는 MethodSecurityExpressionRoot여야 합니다. " +
                            "실제 타입: " + (rootObject != null ? rootObject.getClass() : "null")
            );
        }
    }
}
