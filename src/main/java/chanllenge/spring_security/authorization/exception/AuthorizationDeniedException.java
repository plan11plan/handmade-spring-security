package chanllenge.spring_security.authorization.exception;

public class AuthorizationDeniedException extends RuntimeException {

    public AuthorizationDeniedException(String message) {
        super(message);
    }

    public AuthorizationDeniedException(String message, Throwable cause) {
        super(message, cause);
    }
}
