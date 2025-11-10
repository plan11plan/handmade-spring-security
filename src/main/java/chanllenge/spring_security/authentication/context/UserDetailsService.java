package chanllenge.spring_security.authentication.context;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsService {
    UserDetails loadUserById(Long id) throws UsernameNotFoundException;
}
