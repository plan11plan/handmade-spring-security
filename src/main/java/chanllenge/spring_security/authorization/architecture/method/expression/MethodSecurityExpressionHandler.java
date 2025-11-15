package chanllenge.spring_security.authorization.architecture.method.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;

public interface MethodSecurityExpressionHandler extends SecurityExpressionHandler<MethodInvocation> {
    /**
     * 필터 조건으로 사용해야 하는 표현식입니다.
     */

    Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx);

    /**
     * 주어진 평가 컨텍스트에 대한 반환 개체의 표현 시스템을 알리는 데 사용됩니다. 메서드 호출에만 적용됩니다.
     * @param returnObject
     * @param ctx
     * 여기서 ctx는 -> EvaluationContext  = SecurityExpressionHandler.createEvaluationContext(...) 이걸 이용.
     */
    void setReturnObject(Object returnObject, EvaluationContext ctx);
}
