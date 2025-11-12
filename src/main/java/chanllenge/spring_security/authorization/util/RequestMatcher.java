package chanllenge.spring_security.authorization.util;

@FunctionalInterface
public interface RequestMatcher {

    boolean matches(String url);
}
