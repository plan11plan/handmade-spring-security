package chanllenge.spring_security.authorization.architecture;

import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authorization.architecture.request.RoleHierarchyImpl;
import java.util.Collection;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class RoleHierarchyImplTest {

    @Nested
    @DisplayName("기본 계층 구조 테스트")
    class BasicHierarchyTest {

        @Test
        @DisplayName("단순 계층 구조: ADMIN > USER")
        void simpleHierarchy() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

            Collection<? extends GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));

            Collection<? extends GrantedAuthority> reachableAuthorities =
                    roleHierarchy.getReachableGrantedAuthorities(authorities);

            Assertions.assertThat(reachableAuthorities)
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        }

        @Test
        @DisplayName("3단계 계층 구조: ADMIN > MANAGER > USER")
        void threeLevelHierarchy() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");

            Collection<? extends GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));

            Collection<? extends GrantedAuthority> reachableAuthorities =
                    roleHierarchy.getReachableGrantedAuthorities(authorities);

            Assertions.assertThat(reachableAuthorities)
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_MANAGER", "ROLE_USER");
        }

        @Test
        @DisplayName("중간 역할로 조회: MANAGER는 USER만 포함")
        void middleRoleQuery() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");

            Collection<? extends GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_MANAGER"));

            Collection<? extends GrantedAuthority> reachableAuthorities =
                    roleHierarchy.getReachableGrantedAuthorities(authorities);

            Assertions.assertThat(reachableAuthorities)
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactlyInAnyOrder("ROLE_MANAGER", "ROLE_USER");
        }

        @Test
        @DisplayName("최하위 역할: USER는 자기 자신만")
        void lowestRoleQuery() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");

            Collection<? extends GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_USER"));

            Collection<? extends GrantedAuthority> reachableAuthorities =
                    roleHierarchy.getReachableGrantedAuthorities(authorities);

            Assertions.assertThat(reachableAuthorities)
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_USER");
        }
    }

}
