package chanllenge.spring_security.authorization.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.function.Supplier;
import org.springframework.lang.Nullable;


@FunctionalInterface
public interface AuthorizationManager<T> {

    default void verify(Supplier<Authentication> authentication, T object) {
        AuthorizationResult result = authorize(authentication, object);
        if (result != null && !result.isGranted()) {
            throw new AuthorizationDeniedException("Access Denied", result);
        }
    }

    @Nullable
    AuthorizationResult authorize(Supplier<Authentication> authentication, T object);
}
