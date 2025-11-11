package chanllenge.spring_security.authorization.model;

@FunctionalInterface
public interface AuthorizationResult {
    boolean isGranted();
}
