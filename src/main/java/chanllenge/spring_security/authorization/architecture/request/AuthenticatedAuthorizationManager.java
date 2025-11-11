package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.util.function.Supplier;

public final class AuthenticatedAuthorizationManager<T> implements AuthorizationManager<T> {

    private final AbstractAuthorizationStrategy authorizationStrategy;

    public AuthenticatedAuthorizationManager() {
        this(new AuthenticatedAuthorizationStrategy());
    }

    private AuthenticatedAuthorizationManager(AbstractAuthorizationStrategy authorizationStrategy) {
        this.authorizationStrategy = authorizationStrategy;
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, T object) {
        boolean granted = this.authorizationStrategy.isGranted(authentication.get());
        return new CustomAuthorizationDecision(granted);
    }

    public static <T> AuthenticatedAuthorizationManager<T> authenticated() {
        return new AuthenticatedAuthorizationManager<>();
    }

    public static <T> AuthenticatedAuthorizationManager<T> fullyAuthenticated() {
        return new AuthenticatedAuthorizationManager<>(new FullyAuthenticatedAuthorizationStrategy());
    }

    private abstract static class AbstractAuthorizationStrategy {
        abstract boolean isGranted(Authentication authentication);
    }

    private static class AuthenticatedAuthorizationStrategy extends AbstractAuthorizationStrategy {

        @Override
        boolean isGranted(Authentication authentication) {
            if (authentication == null) {
                return false;
            }
            return authentication.isAuthenticated();
        }
    }

    private static final class FullyAuthenticatedAuthorizationStrategy
            extends AuthenticatedAuthorizationStrategy {

        @Override
        boolean isGranted(Authentication authentication) {
            return super.isGranted(authentication);
        }
    }
}
