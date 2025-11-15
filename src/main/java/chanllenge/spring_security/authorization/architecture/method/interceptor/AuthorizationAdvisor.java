package chanllenge.spring_security.authorization.architecture.method.interceptor;

import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;

public interface AuthorizationAdvisor extends Ordered, PointcutAdvisor, MethodInterceptor, AopInfrastructureBean {

    @Override
    Pointcut getPointcut();

    @Override
    default MethodInterceptor getAdvice() {
        return this;
    }

}
