package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Collection;

public interface RoleHierarchy {

    /**
     * 접근 가능한 모든 권한의 배열을 반환합니다.
     * 	<p>
     * 접근 가능한 권한은 직접 할당된 권한과 역할 계층에서 (전이적으로) 접근할 수 있는 모든 권한입니다.
     * 	<p>	<br>
     * 예: <br>
     * 역할 계층: ROLE_A > ROLE_B > ROLE_C.	<p>
     * 직접 지정된 권한: ROLE_A.	<p>
     * 접근 가능한 권한: ROLE_A, ROLE_B, ROLE_C.	<p>	<br>
     * 매개변수:
     * authorities – - 직접 할당된 권한 목록입니다.	<p>
     * 보고:
     * 할당된 권한이 부여된 모든 접근 가능한 권한 목록입니다.
     */
	Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities);

}
