package chanllenge.spring_security.authorization.architecture.method.expression;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.GrantedAuthority;
import java.util.Arrays;
import java.util.Collection;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MethodSecurityExpressionRootTest {

    @DisplayName("정상적인 Authentication으로 생성 성공")
    @Test
    void createAuthentication() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");

        // expect
        Assertions.assertThatCode(() -> new MethodSecurityExpressionRoot(auth))
                .doesNotThrowAnyException();
    }

    @DisplayName("null Authentication으로 생성 시 예외")
    @Test
    void createAuthentication_nullexception() {
        // expect
        Assertions.assertThatThrownBy(() -> new MethodSecurityExpressionRoot(null))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("ROLE_ 접두사 없이 역할 검사 - 성공")
    @Test
    void haRole_true(){
        // given
        Authentication auth = createAuthentication(true, "ROLE_ADMIN");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasRole("ADMIN");

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("역할이 없으면 false 반환")
    @Test
    void hasRole_false() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasRole("ADMIN");

        // then
        Assertions.assertThat(result).isFalse();
    }

    @DisplayName("여러 역할 중 하나 있으면 성공")
    @Test
    void hasRole_multipleRoles_success() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER", "ROLE_ADMIN");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean resultAdmin = root.hasRole("ADMIN");
        boolean resultUser = root.hasRole("USER");
        boolean resultManager = root.hasRole("MANAGER");

        // then
        Assertions.assertThat(resultAdmin).isTrue();
        Assertions.assertThat(resultUser).isTrue();
        Assertions.assertThat(resultManager).isFalse();
    }

    @DisplayName("정확한 권한 문자열 매칭 - 성공")
    @Test
    void hasAuthority_exactMatch_success() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_ADMIN");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasAuthority("ROLE_ADMIN");

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("ROLE_ 접두사 없는 권한도 검사 가능")
    @Test
    void hasAuthority_withoutRolePrefix() {
        // given
        Authentication auth = createAuthentication(true, "READ", "WRITE");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean resultRead = root.hasAuthority("READ");
        boolean resultWrite = root.hasAuthority("WRITE");
        boolean resultDelete = root.hasAuthority("DELETE");

        // then
        Assertions.assertThat(resultRead).isTrue();
        Assertions.assertThat(resultWrite).isTrue();
        Assertions.assertThat(resultDelete).isFalse();
    }

    @DisplayName("여러 역할 중 하나라도 있으면 true")
    @Test
    void hasAnyRole_oneMatch_returnsTrue() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasAnyRole("ADMIN", "USER", "MANAGER");

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("모든 역할이 없으면 false")
    @Test
    void hasAnyRole_noMatch_returnsFalse() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasAnyRole("ADMIN", "MANAGER");

        // then
        Assertions.assertThat(result).isFalse();
    }

    @DisplayName("여러 권한 중 하나라도 있으면 true")
    @Test
    void hasAnyAuthority_oneMatch_returnsTrue() {
        // given
        Authentication auth = createAuthentication(true, "READ", "WRITE");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasAnyAuthority("READ", "DELETE", "ADMIN");

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("모든 권한이 없으면 false")
    @Test
    void hasAnyAuthority_noMatch_returnsFalse() {
        // given
        Authentication auth = createAuthentication(true, "READ");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.hasAnyAuthority("WRITE", "DELETE", "ADMIN");

        // then
        Assertions.assertThat(result).isFalse();
    }

    @DisplayName("인증된 사용자 - isAuthenticated() true")
    @Test
    void isAuthenticated_authenticatedUser_returnsTrue() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.isAuthenticated();

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("인증되지 않은 사용자 - isAuthenticated() false")
    @Test
    void isAuthenticated_unauthenticatedUser_returnsFalse() {
        // given
        Authentication auth = createAuthentication(false, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.isAuthenticated();

        // then
        Assertions.assertThat(result).isFalse();
    }

    @DisplayName("익명 사용자 (인증되지 않음) - isAnonymous() true")
    @Test
    void isAnonymous_unauthenticatedUser_returnsTrue() {
        // given
        Authentication auth = createAuthentication(false, "ROLE_ANONYMOUS");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.isAnonymous();

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("인증된 사용자는 익명이 아님 - isAnonymous() false")
    @Test
    void isAnonymous_authenticatedUser_returnsFalse() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        boolean result = root.isAnonymous();

        // then
        Assertions.assertThat(result).isFalse();
    }

    @DisplayName("returnObject 설정 및 조회")
    @Test
    void setAndGetReturnObject() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);
        String returnValue = "test-return-value";

        // when
        root.setReturnObject(returnValue);

        // then
        Assertions.assertThat(root.getReturnObject()).isEqualTo(returnValue);
    }

    @DisplayName("returnObject 초기값은 null")
    @Test
    void returnObject_initiallyNull() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        Object result = root.getReturnObject();

        // then
        Assertions.assertThat(result).isNull();
    }

    @DisplayName("target 설정 및 조회")
    @Test
    void setAndGetTarget() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);
        Object targetObject = new Object();

        // when
        root.setTarget(targetObject);

        // then
        Assertions.assertThat(root.getTarget()).isEqualTo(targetObject);
    }

    @DisplayName("getAuthentication()은 Authentication을 반환한다")
    @Test
    void getAuthentication_returnsAuthentication() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        Authentication result = root.getAuthentication();

        // then
        Assertions.assertThat(result).isEqualTo(auth);
    }

    @DisplayName("getPrincipal()은 Principal을 반환한다")
    @Test
    void getPrincipal_returnsPrincipal() {
        // given
        Authentication auth = createAuthentication(true, "ROLE_USER");
        MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(auth);

        // when
        Object result = root.getPrincipal();

        // then
        Assertions.assertThat(result).isEqualTo("test-user");
    }

    private Authentication createAuthentication(boolean authenticated, String... authorities) {
        return new Authentication() {
            @Override
            public String getName() {
                return "test-user";
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return Arrays.stream(authorities)
                        .map(auth -> (GrantedAuthority) () -> auth)
                        .toList();
            }

            @Override
            public Object getPrincipal() {
                return "test-user";
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return authenticated;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            }
        };
    }
}
