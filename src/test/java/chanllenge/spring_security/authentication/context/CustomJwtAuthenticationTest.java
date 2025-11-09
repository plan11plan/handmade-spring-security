package chanllenge.spring_security.authentication.context;

import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CustomJwtAuthenticationTest {

    @DisplayName("userId로 사용자 식별 및 권한 목록 포함")
    @Test
    void createCustomAuthentication() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));

        // expect
        Assertions.assertThatCode(() -> new CustomJwtAuthentication(userId, authorities))
                .doesNotThrowAnyException();
    }

    @DisplayName("인증 상태 -> 참 (JWT는 이미 검증됨, 항상 참)")
    @Test
    void isAuthenticated_true() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.isAuthenticated()).isTrue();
    }

    @DisplayName("null userId -> 예외")
    @Test
    void createCustomAuthentication_null_userId_exception() {
        // given
        Long userId = null;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));

        // expect
        Assertions.assertThatThrownBy(() -> new CustomJwtAuthentication(userId, authorities))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("null authorities -> 예외")
    @Test
    void createCustomAuthentication_null_authorities_exception() {
        // given
        Long userId = 1L;

        // expect
        Assertions.assertThatThrownBy(() -> new CustomJwtAuthentication(userId, null))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("userId 조회")
    @Test
    void getPrincipal() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.getPrincipal()).isEqualTo(1L);
    }

    @DisplayName("getUserId() -> Long 타입 반환")
    @Test
    void getUserId() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        CustomJwtAuthentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.getUserId()).isEqualTo(1L);
        Assertions.assertThat(auth.getUserId()).isInstanceOf(Long.class);
    }

    @DisplayName("권한 목록 조회 가능")
    @Test
    void getAuthorities() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.getAuthorities()).hasSize(1);
        Assertions.assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("USER");
    }

    @DisplayName("여러 권한 포함")
    @Test
    void getAuthorities_multiple() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("USER"),
                new SimpleGrantedAuthority("ADMIN")
        );
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.getAuthorities()).hasSize(2);
        Assertions.assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("USER", "ADMIN");
    }

    @DisplayName("credentials -> null")
    @Test
    void getCredentials_null() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // expect
        Assertions.assertThat(auth.getCredentials()).isNull();
    }

}
