package chanllenge.spring_security.authentication.exception;

public class InvalidTokenException extends AuthenticationException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
