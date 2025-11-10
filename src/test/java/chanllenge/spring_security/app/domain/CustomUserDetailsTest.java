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
        UserRole role = UserRole.USER;

        // expect
        Assertions.assertThatCode(() -> new User(username, role))
                .doesNotThrowAnyException();
    }

    @DisplayName("빈 유저이름 -> 예외")
    @NullAndEmptySource
    @ParameterizedTest
    void createUser_name_blank_exception(String username) {
        // given
        String given = username;
        UserRole role = UserRole.USER;

        // expect
        Assertions.assertThatThrownBy(() -> new User(given, role))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("빈 역할 -> 예외")
    @Test
    void createUser_role_null_exception() {
        // given
        String username = "username";
        UserRole role = null;

        // expect
        Assertions.assertThatThrownBy(() -> new User(username, role))
                .isInstanceOf(Exception.class);
    }
}
