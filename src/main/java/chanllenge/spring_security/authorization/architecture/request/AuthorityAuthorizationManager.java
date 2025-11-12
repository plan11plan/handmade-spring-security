package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.Set;
import java.util.function.Supplier;
import org.springframework.util.Assert;

public final class AuthorityAuthorizationManager<T> implements AuthorizationManager<T> {

    private static final String ERROR_ROLE_NULL = "role은 null일 수 없습니다";
    private static final String ERROR_ROLE_STARTS_WITH_PREFIX = "'%s'는 %s로 시작하면 안 됩니다. hasRole 사용 시 %s가 자동으로 앞에 붙습니다. 대신 hasAuthority 사용을 고려하세요.";
    private static final String ERROR_AUTHORITY_NULL = "authority는 null일 수 없습니다";
    private static final String ERROR_ROLES_EMPTY = "roles는 비어있을 수 없습니다";
    private static final String ERROR_ROLES_CONTAIN_NULL = "roles는 null 값을 포함할 수 없습니다";
    private static final String ERROR_AUTHORITIES_EMPTY = "authorities는 비어있을 수 없습니다";
    private static final String ERROR_AUTHORITIES_CONTAIN_NULL = "authorities는 null 값을 포함할 수 없습니다";
    private static final String ERROR_ROLE_STARTS_WITH_PREFIX_ANY_ROLE = "'%s'는 %s로 시작하면 안 됩니다. hasAnyRole 사용 시 %s가 자동으로 앞에 붙습니다. 대신 hasAnyAuthority 사용을 고려하세요.";

    private static final String ROLE_PREFIX = "ROLE_";

    private final AuthoritiesAuthorizationManager delegate = new AuthoritiesAuthorizationManager();

    private final Set<String> authorities;

    private AuthorityAuthorizationManager(String... authorities) {
        this.authorities = Set.of(authorities);
    }


    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.delegate.setRoleHierarchy(roleHierarchy);
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, T object) {
        return this.delegate.authorize(authentication, this.authorities);
    }

    public static <T> AuthorityAuthorizationManager<T> hasRole(String role) {
        Assert.notNull(role, ERROR_ROLE_NULL);
        Assert.isTrue(!role.startsWith(ROLE_PREFIX),
                () -> String.format(ERROR_ROLE_STARTS_WITH_PREFIX, role, ROLE_PREFIX, ROLE_PREFIX));
        return new AuthorityAuthorizationManager<>(ROLE_PREFIX + role);
    }


    public static <T> AuthorityAuthorizationManager<T> hasAuthority(String authority) {
        Assert.notNull(authority, ERROR_AUTHORITY_NULL);
        return new AuthorityAuthorizationManager<>(authority);
    }

    public static <T> AuthorityAuthorizationManager<T> hasAnyRole(String... roles) {
        Assert.notEmpty(roles, ERROR_ROLES_EMPTY);
        Assert.noNullElements(roles, ERROR_ROLES_CONTAIN_NULL);
        return new AuthorityAuthorizationManager<>(toNamedRolesArray(ROLE_PREFIX, roles));
    }

    public static <T> AuthorityAuthorizationManager<T> hasAnyAuthority(String... authorities) {
        Assert.notEmpty(authorities, ERROR_AUTHORITIES_EMPTY);
        Assert.noNullElements(authorities, ERROR_AUTHORITIES_CONTAIN_NULL);
        return new AuthorityAuthorizationManager<>(authorities);
    }

    private static String[] toNamedRolesArray(String rolePrefix, String[] roles) {
        String[] result = new String[roles.length];
        for (int i = 0; i < roles.length; i++) {
            String role = roles[i];
            Assert.isTrue(rolePrefix.isEmpty() || !role.startsWith(rolePrefix),
                    () -> String.format(ERROR_ROLE_STARTS_WITH_PREFIX_ANY_ROLE, role, rolePrefix, rolePrefix));
            result[i] = rolePrefix + role;
        }
        return result;
    }

    @Override
    public String toString() {
        return "AuthorityAuthorizationManager[authorities=" + this.authorities + "]";
    }
}
