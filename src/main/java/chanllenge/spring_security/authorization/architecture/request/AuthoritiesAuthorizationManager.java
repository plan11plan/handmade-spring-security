package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import java.util.Collection;
import java.util.function.Supplier;
import org.springframework.util.Assert;


public final class AuthoritiesAuthorizationManager implements AuthorizationManager<Collection<String>> {

    private static final String ERROR_ROLE_HIERARCHY_NULL = "roleHierarchy는 null일 수 없습니다";

    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        Assert.notNull(roleHierarchy, ERROR_ROLE_HIERARCHY_NULL);
        this.roleHierarchy = roleHierarchy;
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, Collection<String> authorities) {

        Authentication auth = authentication.get();

        if (auth == null) {
            return new CustomAuthorizationDecision(false);
        }

        Collection<? extends GrantedAuthority> userAuthorities = auth.getAuthorities();

        if (userAuthorities == null || userAuthorities.isEmpty()) {
            return new CustomAuthorizationDecision(false);
        }

        Collection<? extends GrantedAuthority> reachableAuthorities =
                this.roleHierarchy.getReachableGrantedAuthorities(userAuthorities);

        for (GrantedAuthority grantedAuthority : reachableAuthorities) {
            String authority = grantedAuthority.getAuthority();
            if (authorities.contains(authority)) {
                return new CustomAuthorizationDecision(true);
            }
        }

        return new CustomAuthorizationDecision(false);
    }

    @Override
    public String toString() {
        return "AuthoritiesAuthorizationManager[roleHierarchy=" + this.roleHierarchy.getClass().getSimpleName() + "]";
    }
}
