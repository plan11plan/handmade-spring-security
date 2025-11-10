package chanllenge.spring_security.authentication.context;


public class SecurityContextHolder {
    private static final String ERROR_SECURITY_CONTEXT_CANT_NULL = "SecurityContext는 Null일 수 없습니다.";

    private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

    private SecurityContextHolder() {
    }
    public static SecurityContext getContext() {
        SecurityContext context = contextHolder.get();
        if (context == null) {
            context = createEmptyContext();
            contextHolder.set(context);
        }
        return context;
    }

    public static void setContext(SecurityContext context) {
        if (context == null) {
            throw new IllegalArgumentException(ERROR_SECURITY_CONTEXT_CANT_NULL);
        }
        contextHolder.set(context);
    }

    public static void clearContext() {
        contextHolder.remove();
    }

    public static SecurityContext createEmptyContext() {
        return new SecurityContextImpl();
    }
}
