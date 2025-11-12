package chanllenge.spring_security.authentication.context;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import chanllenge.spring_security.authentication.exception.UserNotFoundException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class CustomUserDetailsServiceTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @DisplayName("존재하는 사용자 ID -> 사용자 상세 정보 반환")
    @Test
    void loadUserById_existing_user() {
        // given
        String username = "testuser";
        UserRole role = UserRole.USER;
        User user = new User(username, role);
        User savedUser = userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserById(savedUser.getId());

        // expect
        Assertions.assertThat(foundUser).isNotNull();
        Assertions.assertThat(foundUser.getUsername()).isEqualTo(username);
    }

    @DisplayName("존재하지 않는 사용자 ID -> 예외")
    @Test
    void loadUserById_nonexistent_user_exception() {
        // given
        Long nonexistentId = 999L;

        // expect
        Assertions.assertThatThrownBy(() -> userDetailsService.loadUserById(nonexistentId))
                .isInstanceOf(UserNotFoundException.class);
    }

    @DisplayName("null 사용자 ID -> 예외")
    @Test
    void loadUserById_null_id_exception() {
        // given
        Long userId = null;

        // expect
        Assertions.assertThatThrownBy(() -> userDetailsService.loadUserById(userId))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("사용자 조회 가능")
    @Test
    void loadUser_and_check() {
        // given
        String username = "testuser";
        UserRole role = UserRole.USER;
        User user = new User(username, role);
        User savedUser = userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserById(savedUser.getId());

        // expect
        Assertions.assertThat(foundUser).isNotNull();
        Assertions.assertThat(foundUser.getUsername()).isEqualTo(username);
        Assertions.assertThat(foundUser.getAuthorities()).hasSize(1);
    }

    @DisplayName("여러 사용자 관리")
    @Test
    void loadMultipleUsers() {
        // given
        User user1 = new User("user1", UserRole.USER);
        User user2 = new User("user2", UserRole.ADMIN);
        User savedUser1 = userRepository.save(user1);
        User savedUser2 = userRepository.save(user2);

        // expect
        Assertions.assertThat(userDetailsService.loadUserById(savedUser1.getId()).getUsername()).isEqualTo("user1");
        Assertions.assertThat(userDetailsService.loadUserById(savedUser2.getId()).getUsername()).isEqualTo("user2");
    }

    @DisplayName("권한 목록 조회 가능")
    @Test
    void loadUserById_check_authorities() {
        // given
        String username = "adminuser";
        UserRole role = UserRole.ADMIN;
        User user = new User(username, role);
        User savedUser = userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserById(savedUser.getId());

        // expect
        Assertions.assertThat(foundUser.getAuthorities()).hasSize(1);
        Assertions.assertThat(foundUser.getAuthorities())
                .extracting(authority -> authority.getAuthority())
                .contains("ADMIN");
    }
}
