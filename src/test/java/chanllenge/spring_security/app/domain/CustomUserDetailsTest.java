package chanllenge.spring_security.app.domain;

import static org.junit.jupiter.api.Assertions.*;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class CustomUserDetailsTest {
    @DisplayName("정상적으로 유저를 생성한다.")
    @Test
    void createUser() {
        // given
        String username = "username";
        String password = "password";
        UserRole role = UserRole.USER;

        // expect
        Assertions.assertThatCode(() -> new User(username,password,role))
                .doesNotThrowAnyException();
    }
    @DisplayName("빈 유저이름 -> 예외")
    @NullAndEmptySource
    @ParameterizedTest
    void createUser_name_blank_exception(String username) {
        // given
        String given = username;
        String password = "password";
        UserRole role = UserRole.USER;

        // expect
        Assertions.assertThatThrownBy(() -> new User(given,password,role))
                .isInstanceOf(Exception.class);
    }
    @DisplayName("빈 패스워드 -> 예외")
    @NullAndEmptySource
    @ParameterizedTest
    void createUser_password_blank_exception(String password) {
        // given
        String username = "username";
        String given = password;
        UserRole role = UserRole.USER;

        // expect
        Assertions.assertThatThrownBy(() -> new User(username,given,role))
                .isInstanceOf(Exception.class);
    }
    @DisplayName("빈 역힐 -> 예외")
    @NullAndEmptySource
    @ParameterizedTest
    void createUser_role_blank_exception(String role) {
        // given
        String username = "username";
        String password = "password";

        // expect
        Assertions.assertThatThrownBy(() -> new User(username,password,UserRole.from(role)))
                .isInstanceOf(Exception.class);
    }
}
