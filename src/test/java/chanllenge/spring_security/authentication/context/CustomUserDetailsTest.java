package chanllenge.spring_security.authentication.context;

import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class CustomUserDetailsTest {

    @DisplayName("유효한 CustomUserDetails -> 변환 성공")
    @Test
    void createUserDetails() {
        // given
        String username = "user";
        String password = "pass";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // expect
        Assertions.assertThatCode(() -> new CustomUserDetails(username, password, authorities))
                .doesNotThrowAnyException();
    }

    @DisplayName("빈 username -> 예외")
    @NullAndEmptySource
    @ParameterizedTest
    void createUserDetails_username_blank_exception(String username) {
        // given
        String given = username;
        String password = "password";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // expect
        Assertions.assertThatThrownBy(() -> new CustomUserDetails(given, password, authorities))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("null password -> 예외")
    @Test
    void createUserDetails_password_null_exception() {
        // given
        String username = "username";
        String password = null;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        // expect
        Assertions.assertThatThrownBy(() -> new CustomUserDetails(username, password, authorities))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("사용자 이름 조회 가능")
    @Test
    void getUsername() {
        // given
        String username = "user";
        String password = "pass";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails userDetails = new CustomUserDetails(username, password, authorities);

        // expect
        Assertions.assertThat(userDetails.getUsername()).isEqualTo("user");
    }

    @DisplayName("비밀번호 조회 가능")
    @Test
    void getPassword() {
        // given
        String username = "user";
        String password = "pass";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails userDetails = new CustomUserDetails(username, password, authorities);

        // expect
        Assertions.assertThat(userDetails.getPassword()).isEqualTo("pass");
    }

    @DisplayName("권한 목록 조회 가능")
    @Test
    void getAuthorities() {
        // given
        String username = "user";
        String password = "pass";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails userDetails = new CustomUserDetails(username, password, authorities);

        // expect
        Assertions.assertThat(userDetails.getAuthorities()).hasSize(1);
        Assertions.assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @DisplayName("권한 목록 조회 가능 - 여러 권한")
    @Test
    void getAuthorities_multiple() {
        // given
        String username = "user";
        String password = "pass";
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN")
        );
        UserDetails userDetails = new CustomUserDetails(username, password, authorities);

        // expect
        Assertions.assertThat(userDetails.getAuthorities()).hasSize(2);
        Assertions.assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }
}
