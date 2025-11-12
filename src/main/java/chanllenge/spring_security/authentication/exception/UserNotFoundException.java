package chanllenge.spring_security.authentication.exception;

public class UserNotFoundException extends AuthenticationException {

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
