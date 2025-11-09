package chanllenge.spring_security.authentication.context;

import java.util.List;

public interface UserDetails {
    List<GrantedAuthority> getAuthorities();

    String getPassword();

    String getUsername();

}
