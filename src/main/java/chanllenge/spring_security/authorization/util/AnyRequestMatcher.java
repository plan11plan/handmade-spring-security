package chanllenge.spring_security.authorization.util;

public final class AnyRequestMatcher implements RequestMatcher {

    public static final AnyRequestMatcher INSTANCE = new AnyRequestMatcher();

    private AnyRequestMatcher() {
    }

    @Override
    public boolean matches(String url) {
        return true;
    }

    @Override
    public String toString() {
        return "AnyRequestMatcher[]";
    }
}
