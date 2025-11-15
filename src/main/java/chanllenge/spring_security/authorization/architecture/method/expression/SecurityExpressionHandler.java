package chanllenge.spring_security.authorization.architecture.method.expression;

import chanllenge.spring_security.authentication.context.Authentication;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;

public interface SecurityExpressionHandler<T> extends AopInfrastructureBean {

    ExpressionParser getExpressionParser();

    EvaluationContext createEvaluationContext(Authentication authentication, T invocation);
}
