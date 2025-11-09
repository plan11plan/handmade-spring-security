package chanllenge.spring_security.authentication.context;

import java.util.Objects;
import org.springframework.util.Assert;

public final class SimpleGrantedAuthority implements GrantedAuthority {
    private static final String ERROR_ROLE_TEXT_EMPTY = "role 문자열이 비어있습니다";

    private final String role;

    public SimpleGrantedAuthority(String role) {
        Assert.hasText(role, ERROR_ROLE_TEXT_EMPTY);
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return this.role;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof SimpleGrantedAuthority that)) {
            return false;
        }
        return Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {
        return this.role.hashCode();
    }

    @Override
    public String toString() {
        return this.role;
    }

}
