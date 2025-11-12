package chanllenge.spring_security.authorization.exception;

import chanllenge.spring_security.authorization.model.AuthorizationResult;


public class AuthorizationDeniedException extends RuntimeException {

    private final AuthorizationResult authorizationResult;

    public AuthorizationDeniedException(String message) {
        this(message, (AuthorizationResult) null);
    }

    public AuthorizationDeniedException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public AuthorizationDeniedException(String message, AuthorizationResult authorizationResult) {
        super(message);
        this.authorizationResult = authorizationResult;
    }

    public AuthorizationDeniedException(String message, AuthorizationResult authorizationResult, Throwable cause) {
        super(message, cause);
        this.authorizationResult = authorizationResult;
    }

    public AuthorizationResult getAuthorizationResult() {
        return this.authorizationResult;
    }
}
