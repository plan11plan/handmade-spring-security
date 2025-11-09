package chanllenge.spring_security.authentication.context;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class SimpleGrantedAuthorityTest {

    @Test
    @DisplayName("권한을 표현한다.")
    void present_authority() {
        // given
        String role = "ROLE_USER";

        // when
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role);

        // then
        Assertions.assertThat(grantedAuthority.getAuthority()).isEqualTo(role);
    }

    @NullAndEmptySource
    @DisplayName("빈 권한 -> 예외")
    @ParameterizedTest
    void authority_empty_exception (String empty) {
        // given
        String role = empty;

        // expect
        org.assertj.core.api.Assertions.assertThatCode( () -> new SimpleGrantedAuthority(role))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("같은 권한이면 동일하다고 판단")
    void same_authority_then_same() {
        // given
        String ROLE_USER = "ROLE_USER";
        String ROLE_ADMIN = "ROLE_ADMIN";
        GrantedAuthority grantedAuthority1 = new SimpleGrantedAuthority(ROLE_USER);
        GrantedAuthority grantedAuthority2 = new SimpleGrantedAuthority(ROLE_USER);

        // expect
        Assertions.assertThat(grantedAuthority1.getAuthority()).isEqualTo(grantedAuthority2.getAuthority());
    }
    @Test
    @DisplayName("다른 권한이면 다르다고 판단")
    void different_authority_then_different() {
        // given
        String ROLE_USER = "ROLE_USER";
        String ROLE_ADMIN = "ROLE_ADMIN";
        GrantedAuthority grantedAuthority1 = new SimpleGrantedAuthority(ROLE_USER);
        GrantedAuthority grantedAuthority2 = new SimpleGrantedAuthority(ROLE_ADMIN);

        // expect
        Assertions.assertThat(grantedAuthority1.getAuthority()).isNotEqualTo(grantedAuthority2.getAuthority());
    }

}
