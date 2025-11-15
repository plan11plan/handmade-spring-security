package chanllenge.spring_security.authorization.architecture.method.expression;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.springframework.util.Assert;

public class MethodSecurityExpressionRoot {

    private final Authentication authentication;
    private Object returnObject;
    private Object target;

    public MethodSecurityExpressionRoot(Authentication authentication) {
        Assert.notNull(authentication, "Authentication은 null일 수 없습니다.");
        this.authentication = authentication;
    }

    public boolean hasRole(String role) {
        return hasAnyAuthority("ROLE_" + role);
    }

    public boolean hasAuthority(String authority) {
        return getAuthoritySet().contains(authority);
    }

    public boolean hasAnyRole(String... roles) {
        String[] roleAuthorities = Arrays.stream(roles)
                .map(role -> "ROLE_" + role)
                .toArray(String[]::new);
        return hasAnyAuthority(roleAuthorities);
    }

    public boolean hasAnyAuthority(String... authorities) {
        Set<String> userAuthorities = getAuthoritySet();
        for (String authority : authorities) {
            if (userAuthorities.contains(authority)) {
                return true;
            }
        }
        return false;
    }

    public boolean isAnonymous() {
        return !isAuthenticated();
    }

    public boolean isAuthenticated() {
        return authentication != null && authentication.isAuthenticated();
    }

    public final Authentication getAuthentication() {
        return this.authentication;
    }

    public Object getPrincipal() {
        return this.authentication.getPrincipal();
    }

    public Object getReturnObject() {
        return this.returnObject;
    }

    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    public Object getTarget() {
        return this.target;
    }

    public void setTarget(Object target) {
        this.target = target;
    }

    private Set<String> getAuthoritySet() {
        Collection<? extends GrantedAuthority> authorities = this.authentication.getAuthorities();
        Set<String> authoritySet = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            authoritySet.add(authority.getAuthority());
        }
        return authoritySet;
    }
}
