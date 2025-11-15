package chanllenge.spring_security.authentication.exception;

public class AuthenticationCredentialsNotFoundException extends AuthenticationException {
    public AuthenticationCredentialsNotFoundException(String msg) {
        super(msg);
    }
    public AuthenticationCredentialsNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
