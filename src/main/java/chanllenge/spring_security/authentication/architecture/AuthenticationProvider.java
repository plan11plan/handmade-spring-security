package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.exception.AuthenticationException;

public interface AuthenticationProvider {

    Authentication authenticate(Authentication authentication) throws AuthenticationException;

    boolean supports(Class<?> authentication);

}
