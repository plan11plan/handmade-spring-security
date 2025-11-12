package chanllenge.spring_security.authentication.context;

import chanllenge.spring_security.authentication.exception.UserNotFoundException;

public interface UserDetailsService {
    UserDetails loadUserById(Long id) throws UserNotFoundException;
}
