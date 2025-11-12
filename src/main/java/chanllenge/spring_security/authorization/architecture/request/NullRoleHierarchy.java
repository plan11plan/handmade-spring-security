package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Collection;

public final class NullRoleHierarchy implements RoleHierarchy {

	@Override
	public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities) {
		return authorities;
	}

}
