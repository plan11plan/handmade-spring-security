package chanllenge.spring_security.authorization.model;

import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Collection;


public class CustomAuthorityAuthorizationDecision extends CustomAuthorizationDecision {
    private final Collection<GrantedAuthority> authorities;

    public CustomAuthorityAuthorizationDecision(boolean granted, Collection<GrantedAuthority> authorities) {
        super(granted);
        this.authorities = authorities;
    }
    public Collection<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }
}
