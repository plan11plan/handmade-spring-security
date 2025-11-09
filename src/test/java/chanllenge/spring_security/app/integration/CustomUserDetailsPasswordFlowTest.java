package chanllenge.spring_security.app.integration;

import static org.assertj.core.api.Assertions.assertThat;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserService;
import chanllenge.spring_security.app.infrastructure.crypto.PasswordEncoder;
import jakarta.transaction.Transactional;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Transactional
class CustomUserDetailsPasswordFlowTest {

    @Autowired
    UserService userService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("유저를 생성하고 비밀번호를 암호화하여 저장한다")
    void registerUser_encryptsPasswordAndSave() {
        // given
        String username = "username";
        String rawPassword = "12345";
        String role = "USER";

        // when
        userService.registerUser(username, rawPassword, role);

        // then
        Optional<User> saved = userRepository.findByUsername(username);
        assertThat(saved).isPresent();
        User user = saved.get();
        assertThat(user.getUsername()).isEqualTo(username);
        assertThat(user.getPassword()).isNotEqualTo(rawPassword);
        assertThat(passwordEncoder.matches(rawPassword, user.getPassword())).isTrue();
    }
    @Test
    @DisplayName("저장된 유저의 비밀번호를 검증한다")
    void verifyPassword_check_StoredUserPassword() {
        // given
        String username = "username";
        String rawPassword = "12345";
        String wrongPassword = "wrong-password";
        String role = "USER";
        userService.registerUser(username, rawPassword, role);

        // when
        boolean correct = userService.verifyPassword(username, rawPassword);
        boolean wrong = userService.verifyPassword(username, wrongPassword);

        // then
        assertThat(correct).isTrue();
        assertThat(wrong).isFalse();
    }
}
