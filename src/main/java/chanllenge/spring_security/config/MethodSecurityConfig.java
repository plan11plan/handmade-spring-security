package chanllenge.spring_security.config;

import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.expression.DefaultMethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.expression.MethodSecurityExpressionHandler;
import chanllenge.spring_security.authorization.architecture.method.interceptor.AuthorizationManagerAfterMethodInterceptor;
import chanllenge.spring_security.authorization.architecture.method.interceptor.AuthorizationManagerBeforeMethodInterceptor;
import chanllenge.spring_security.authorization.architecture.method.interceptor.MethodInvocationResult;
import chanllenge.spring_security.authorization.architecture.method.manager.PostAuthorizeAuthorizationManager;
import chanllenge.spring_security.authorization.architecture.method.manager.PreAuthorizeAuthorizationManager;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class MethodSecurityConfig {

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        return new DefaultMethodSecurityExpressionHandler();
    }

    @Bean("customPreAuthorizeAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor preAuthorize(MethodSecurityExpressionHandler expressionHandler) {
        AuthorizationManager<MethodInvocation> manager = new PreAuthorizeAuthorizationManager(expressionHandler);
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager);
    }

    @Bean("customPostAuthorizeAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor postAuthorize(MethodSecurityExpressionHandler expressionHandler) {
        AuthorizationManager<MethodInvocationResult> manager = new PostAuthorizeAuthorizationManager(expressionHandler);
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize(manager);
    }
}

