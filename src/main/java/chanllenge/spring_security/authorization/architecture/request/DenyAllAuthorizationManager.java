package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.util.function.Supplier;

public final class DenyAllAuthorizationManager<T> implements AuthorizationManager<T> {

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, T object) {
        return new CustomAuthorizationDecision(false);
    }
}
