package chanllenge.spring_security.authorization.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import chanllenge.spring_security.authorization.architecture.request.AuthenticatedAuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import java.util.Collection;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AuthenticatedAuthorizationManagerTest {

    @Test
    @DisplayName("authenticated() - 인증된 사용자 허용")
    void authenticated_authenticatedUser_granted() {
        // given
        Authentication auth = new CustomJwtAuthentication(1L, List.of());
        AuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();

        // when
        AuthorizationResult result = manager.authorize(() -> auth, null);

        // then
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    @Test
    @DisplayName("authenticated() - 인증되지 않은 사용자 거부")
    void authenticated_unauthenticatedUser_denied() {
        // given
        Authentication auth = createUnauthenticatedAuthentication();
        AuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();

        // when
        AuthorizationResult result = manager.authorize(() -> auth, null);

        // then
        Assertions.assertThat(result.isGranted()).isFalse();
    }

    @Test
    @DisplayName("authenticated() - 권한과 무관하게 인증만 확인")
    void authenticated_ignoresAuthorities_checksOnlyAuthentication() {
        // given
        Authentication authWithoutAuthorities = new CustomJwtAuthentication(1L, List.of());
        AuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.authenticated();

        // when
        AuthorizationResult result = manager.authorize(() -> authWithoutAuthorities, null);

        // then
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    @Test
    @DisplayName("fullyAuthenticated() - 인증된 사용자 허용")
    void fullyAuthenticated_authenticatedUser_granted() {
        // given
        Authentication auth = new CustomJwtAuthentication(1L, List.of());
        AuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();

        // when
        AuthorizationResult result = manager.authorize(() -> auth, null);

        // then
        Assertions.assertThat(result.isGranted()).isTrue();
    }

    @Test
    @DisplayName("fullyAuthenticated() - 인증되지 않은 사용자 거부")
    void fullyAuthenticated_unauthenticatedUser_denied() {
        // given
        Authentication auth = createUnauthenticatedAuthentication();
        AuthorizationManager<Object> manager = AuthenticatedAuthorizationManager.fullyAuthenticated();

        // when
        AuthorizationResult result = manager.authorize(() -> auth, null);

        // then
        Assertions.assertThat(result.isGranted()).isFalse();
    }


    private Authentication createUnauthenticatedAuthentication() {
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
                return List.of();
            }

            @Override
            public boolean isAuthenticated() {
                return false;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
                // no-op
            }

            @Override
            public String getName() {
                return "unauthenticated";
            }
        };
    }
}
