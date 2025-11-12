package chanllenge.spring_security.authorization.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authorization.architecture.request.AuthorityAuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.Collection;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class AuthorityAuthorizationManagerTest {

    @Nested
    @DisplayName("hasRole() 테스트")
    class HasRoleTest {

        @Test
        @DisplayName("ROLE_ 접두사를 자동으로 추가한다")
        void automaticallyAddsRolePrefix() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("권한이 없으면 거부한다")
        void deniesWhenNoAuthority() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("ROLE_로 시작하는 경우 예외를 발생시킨다")
        void throwsExceptionWhenRoleStartsWithPrefix() {
            Assertions.assertThatThrownBy(() -> AuthorityAuthorizationManager.hasRole("ROLE_ADMIN"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("hasAuthority() 테스트")
    class HasAuthorityTest {

        @Test
        @DisplayName("권한 문자열을 ROLE_ 접두사 없이 검사한다")
        void checksExactAuthority() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("WRITE")));
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAuthority("WRITE");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }
    }

    @Nested
    @DisplayName("hasAnyRole() 테스트 - OR 조건")
    class HasAnyRoleTest {

        @Test
        @DisplayName("여러 역할 중 하나라도 있으면 허용한다")
        void grantsWhenAnyRoleMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_MANAGER")));
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyRole("ADMIN", "MANAGER");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("여러 역할 중 첫 번째 역할만 있어도 허용한다")
        void grantsWhenFirstRoleMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyRole("ADMIN", "MANAGER", "USER");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("역할이 하나도 없으면 거부한다")
        void deniesWhenNoRoleMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyRole("ADMIN", "MANAGER");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("hasAnyAuthority() 테스트 - OR 조건")
    class HasAnyAuthorityTest {

        @Test
        @DisplayName("여러 권한 중 하나라도 있으면 허용한다")
        void grantsWhenAnyAuthorityMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("WRITE")));
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyAuthority("READ", "WRITE");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("권한이 하나도 없으면 거부한다")
        void deniesWhenNoAuthorityMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("DELETE")));
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyAuthority("READ", "WRITE");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("null 테스트")
    class NullSafetyTest {

        @Test
        @DisplayName("Authentication이 null이면 거부한다")
        void deniesWhenAuthenticationIsNull() {
            // given
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

            // when
            AuthorizationResult result = manager.authorize(() -> null, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("권한 목록이 비어있으면 거부한다")
        void deniesWhenAuthoritiesAreEmpty() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L, List.of());
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("권한 목록이 null이면 거부한다")
        void deniesWhenAuthoritiesAreNull() {
            // given
            Authentication auth = createAuthenticationWithNullAuthorities();
            AuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("OR 조건 동작 검증")
    class OrConditionTest {

        @Test
        @DisplayName("여러 권한 중 하나만 있어도 허용한다")
        void grantsWhenOneMatchIsEnough() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));

            // ROLE_ADMIN 또는 ROLE_MANAGER 또는 ROLE_USER 중 하나라도 있으면 허용
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyRole("ADMIN", "MANAGER", "USER");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("여러 권한을 모두 가지고 있어도 허용한다")
        void grantsWhenMultipleMatches() {
            // given
            Authentication auth = new CustomJwtAuthentication(1L,
                    List.of(
                            new SimpleGrantedAuthority("ROLE_ADMIN"),
                            new SimpleGrantedAuthority("ROLE_USER")
                    ));

            // ROLE_ADMIN 또는 ROLE_MANAGER 중 하나라도 있으면 허용
            AuthorizationManager<Object> manager =
                    AuthorityAuthorizationManager.hasAnyRole("ADMIN", "MANAGER");

            // when
            AuthorizationResult result = manager.authorize(() -> auth, null);

            // then
            Assertions.assertThat(result.isGranted()).isTrue();
        }
    }

    private Authentication createAuthenticationWithNullAuthorities() {
        return new Authentication() {
            @Override
            public Object getPrincipal() {
                return 1L;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return true;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
                // no-op
            }

            @Override
            public String getName() {
                return "test";
            }
        };
    }
}
