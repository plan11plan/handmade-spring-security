package chanllenge.spring_security.authorization.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authorization.architecture.request.RequestMatcherDelegatingAuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.util.AntPathRequestMatcher;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("RequestMatcherDelegatingAuthorizationManager 테스트")
class RequestMatcherDelegatingAuthorizationManagerTest {

    @Nested
    @DisplayName("Builder 기본 동작")
    class BuilderBasicTest {

        @Test
        @DisplayName("add()와 build()로 매니저 생성")
        void basicBuildWithAdd() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
                            .build();

            Assertions.assertThat(manager).isNotNull();
        }

        @Test
        @DisplayName("빈 매핑으로 빌드 시 예외")
        void buildWithEmptyMappings() {
            Assertions.assertThatThrownBy(() ->
                            RequestMatcherDelegatingAuthorizationManager.builder().build())
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("AuthorizedUrl DSL")
    class AuthorizedUrlDslTest {

        @Test
        @DisplayName("permitAll()로 모든 요청 허용")
        void permitAllAllows() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/public/**")).permitAll()
                            .build();

            Authentication guest = null;
            AuthorizationResult result = manager.authorize(() -> guest, "/public/login");

            Assertions.assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("denyAll()로 모든 요청 거부")
        void denyAllDenies() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/private/**")).denyAll()
                            .build();

            Authentication admin = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            AuthorizationResult result = manager.authorize(() -> admin, "/private/secret");

            Assertions.assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("authenticated()로 인증된 사용자만 허용")
        void authenticatedRequiresAuth() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/api/**")).authenticated()
                            .build();

            Authentication user = new CustomJwtAuthentication(1L, List.of());
            Assertions.assertThat(manager.authorize(() -> user, "/api/data").isGranted()).isTrue();

            Authentication guest = null;
            Assertions.assertThat(manager.authorize(() -> guest, "/api/data").isGranted()).isFalse();
        }

        @Test
        @DisplayName("hasRole()로 특정 역할 검사")
        void hasRoleChecksRole() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
                            .build();

            Authentication admin = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            Assertions.assertThat(manager.authorize(() -> admin, "/admin/dashboard").isGranted()).isTrue();

            Authentication user = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            Assertions.assertThat(manager.authorize(() -> user, "/admin/dashboard").isGranted()).isFalse();
        }

        @Test
        @DisplayName("hasAnyRole()로 여러 역할 중 하나 검사")
        void hasAnyRoleChecksMultipleRoles() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/staff/**")).hasAnyRole("ADMIN", "MANAGER")
                            .build();

            Authentication admin = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
            Assertions.assertThat(manager.authorize(() -> admin, "/staff/reports").isGranted()).isTrue();

            Authentication staffManager = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_MANAGER")));
            Assertions.assertThat(manager.authorize(() -> staffManager, "/staff/reports").isGranted()).isTrue();

            Authentication user = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));
            Assertions.assertThat(manager.authorize(() -> user, "/staff/reports").isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("anyRequest() 동작")
    class AnyRequestTest {

        @Test
        @DisplayName("anyRequest()로 기본 정책 설정")
        void anyRequestSetsDefaultPolicy() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .anyRequest().denyAll()
                            .build();

            Authentication auth = new CustomJwtAuthentication(1L, List.of());
            AuthorizationResult result = manager.authorize(() -> auth, "/any/url");

            Assertions.assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("anyRequest() 중복 호출 시 예외")
        void anyRequestDuplicate() {
            Assertions.assertThatThrownBy(() ->
                            RequestMatcherDelegatingAuthorizationManager.builder()
                                    .anyRequest().permitAll()
                                    .anyRequest().denyAll())
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    @DisplayName("패턴 매칭 순서")
    class PatternMatchingOrderTest {

        @Test
        @DisplayName("첫 번째 매칭되는 패턴 사용 (first-match)")
        void firstMatchWins() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
                            .requestMatchers(new AntPathRequestMatcher("/**")).permitAll()
                            .build();

            Authentication user = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));

            Assertions.assertThat(manager.authorize(() -> user, "/admin/dashboard").isGranted()).isFalse();
            Assertions.assertThat(manager.authorize(() -> user, "/public/page").isGranted()).isTrue();
        }

        @Test
        @DisplayName("매칭 실패 시 거부")
        void noMatchDenies() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
                            .build();

            Authentication user = new CustomJwtAuthentication(1L,
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));

            AuthorizationResult result = manager.authorize(() -> user, "/unknown/path");

            Assertions.assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("실전 시나리오")
    class RealWorldScenarioTest {

        @Test
        @DisplayName("API 권한 설정 테스트")
        void ecommerceApiAuthorization() {
            RequestMatcherDelegatingAuthorizationManager manager =
                    RequestMatcherDelegatingAuthorizationManager.builder()
                            .requestMatchers(new AntPathRequestMatcher("/api/admin/**")).hasRole("ADMIN")
                            .requestMatchers(new AntPathRequestMatcher("/api/seller/**")).hasAnyRole("ADMIN", "SELLER")
                            .requestMatchers(new AntPathRequestMatcher("/api/orders/**")).authenticated()
                            .requestMatchers(new AntPathRequestMatcher("/api/products/**")).permitAll()
                            .anyRequest().denyAll()
                            .build();

            Authentication admin = createAuth("ROLE_ADMIN");
            Authentication seller = createAuth("ROLE_SELLER");
            Authentication customer = createAuth("ROLE_CUSTOMER");
            Authentication guest = null;

            Assertions.assertThat(manager.authorize(() -> admin, "/api/admin/users").isGranted()).isTrue();
            Assertions.assertThat(manager.authorize(() -> seller, "/api/admin/users").isGranted()).isFalse();

            Assertions.assertThat(manager.authorize(() -> admin, "/api/seller/inventory").isGranted()).isTrue();
            Assertions.assertThat(manager.authorize(() -> seller, "/api/seller/inventory").isGranted()).isTrue();
            Assertions.assertThat(manager.authorize(() -> customer, "/api/seller/inventory").isGranted()).isFalse();

            Assertions.assertThat(manager.authorize(() -> customer, "/api/orders/my").isGranted()).isTrue();
            Assertions.assertThat(manager.authorize(() -> guest, "/api/orders/my").isGranted()).isFalse();

            Assertions.assertThat(manager.authorize(() -> guest, "/api/products/list").isGranted()).isTrue();

            Assertions.assertThat(manager.authorize(() -> admin, "/unknown/path").isGranted()).isFalse();
        }

        private Authentication createAuth(String role) {
            return new CustomJwtAuthentication(1L, List.of(new SimpleGrantedAuthority(role)));
        }
    }
}
