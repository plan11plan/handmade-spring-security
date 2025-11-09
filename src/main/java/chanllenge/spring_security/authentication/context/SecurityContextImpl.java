package chanllenge.spring_security.authentication.context;

import java.util.Objects;

public class SecurityContextImpl implements SecurityContext {

    private Authentication authentication;

    public SecurityContextImpl() {
    }

    public SecurityContextImpl(Authentication authentication) {
        this.authentication = authentication;
    }

    @Override
    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    @Override
    public Authentication getAuthentication() {
        return authentication;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SecurityContextImpl that)) {
            return false;
        }
        return Objects.equals(authentication, that.authentication);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(authentication);
    }
}
