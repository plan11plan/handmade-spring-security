package chanllenge.spring_security.authentication.context;

import java.security.Principal;
import java.util.Collection;

public interface Authentication extends Principal {
    Object getPrincipal();

    Object getCredentials();

    Collection<? extends GrantedAuthority> getAuthorities();

    boolean isAuthenticated();

    void setAuthenticated(boolean isAuthenticated);
}
