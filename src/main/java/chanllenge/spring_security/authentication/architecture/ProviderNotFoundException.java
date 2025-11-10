package chanllenge.spring_security.authentication.architecture;

import org.springframework.security.core.AuthenticationException;

/**
 * 인증을 처리할 수 있는 AuthenticationProvider를 찾을 수 없을 때 발생하는 예외
 */
public class ProviderNotFoundException extends AuthenticationException {
    public ProviderNotFoundException(String message) {
        super(message);
    }

    public ProviderNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
