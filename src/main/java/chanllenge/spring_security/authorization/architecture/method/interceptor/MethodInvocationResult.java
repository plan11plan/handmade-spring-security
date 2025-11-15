package chanllenge.spring_security.authorization.architecture.method.interceptor;

import org.aopalliance.intercept.MethodInvocation;

public final class MethodInvocationResult {

    private final MethodInvocation methodInvocation;
    private final Object result;

    public MethodInvocationResult(MethodInvocation methodInvocation, Object result) {
        if (methodInvocation == null) {
            throw new IllegalArgumentException("MethodInvocation은 null일 수 없습니다.");
        }
        this.methodInvocation = methodInvocation;
        this.result = result;
    }

    public MethodInvocation getMethodInvocation() {
        return this.methodInvocation;
    }

    public Object getResult() {
        return this.result;
    }

}
