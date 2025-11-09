package chanllenge.spring_security.authentication.context;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class CustomUserDetailsServiceTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserDetailsService userDetailsService;

    @DisplayName("존재하는 사용자 이름 -> 사용자 상세 정보 반환")
    @Test
    void loadUserByUsername_existing_user() {
        // given
        String username = "user";
        String password = "pass";
        UserRole role = UserRole.USER;
        User user = new User(username, password, role);
        userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserByUsername(username);

        // expect
        Assertions.assertThat(foundUser).isNotNull();
        Assertions.assertThat(foundUser.getUsername()).isEqualTo(username);
    }

    @DisplayName("존재하지 않는 사용자 이름 -> 예외")
    @Test
    void loadUserByUsername_nonexistent_user_exception() {
        // given
        String username = "nonexistent";

        // expect
        Assertions.assertThatThrownBy(() -> userDetailsService.loadUserByUsername(username))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @DisplayName("null 사용자 이름 -> 예외")
    @Test
    void loadUserByUsername_null_username_exception() {
        // given
        String username = null;

        // expect
        Assertions.assertThatThrownBy(() -> userDetailsService.loadUserByUsername(username))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("빈 사용자 이름 -> 예외")
    @Test
    void loadUserByUsername_empty_username_exception() {
        // given
        String username = "";

        // expect
        Assertions.assertThatThrownBy(() -> userDetailsService.loadUserByUsername(username))
                .isInstanceOf(Exception.class);
    }

    @DisplayName("사용자 조회 가능")
    @Test
    void loadUser_and_check() {
        // given
        String username = "testuser";
        String password = "testpass";
        UserRole role = UserRole.USER;
        User user = new User(username, password, role);
        userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserByUsername(username);

        // expect
        Assertions.assertThat(foundUser).isNotNull();
        Assertions.assertThat(foundUser.getUsername()).isEqualTo(username);
        Assertions.assertThat(foundUser.getAuthorities()).hasSize(1);
    }

    @DisplayName("여러 사용자 관리")
    @Test
    void loadMultipleUsers() {
        // given
        User user1 = new User("user1", "pass1", UserRole.USER);
        User user2 = new User("user2", "pass2", UserRole.ADMIN);
        userRepository.save(user1);
        userRepository.save(user2);

        // expect
        Assertions.assertThat(userDetailsService.loadUserByUsername("user1").getUsername()).isEqualTo("user1");
        Assertions.assertThat(userDetailsService.loadUserByUsername("user2").getUsername()).isEqualTo("user2");
    }

    @DisplayName("권한 목록 조회 가능")
    @Test
    void loadUserByUsername_check_authorities() {
        // given
        String username = "adminuser";
        String password = "adminpass";
        UserRole role = UserRole.ADMIN;
        User user = new User(username, password, role);
        userRepository.save(user);

        // when
        UserDetails foundUser = userDetailsService.loadUserByUsername(username);

        // expect
        Assertions.assertThat(foundUser.getAuthorities()).hasSize(1);
        Assertions.assertThat(foundUser.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ADMIN");
    }
}
