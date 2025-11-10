package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class CustomJwtAuthenticationProviderTest {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserRepository userRepository;
    private CustomJwtAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        provider = new CustomJwtAuthenticationProvider(userDetailsService);
    }

    @DisplayName("인증 객체의 인증정보를 검증한다.")
    @Test
    void authenticate() {
        // given
        User user = userRepository.save(new User("testuser", UserRole.USER));
        Authentication authentication = new CustomJwtAuthentication(
                user.getId(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // when
        Authentication result = provider.authenticate(authentication);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.isAuthenticated()).isTrue();
        Assertions.assertThat(result).isInstanceOf(CustomJwtAuthentication.class);
        Assertions.assertThat(((CustomJwtAuthentication) result).getUserId()).isEqualTo(user.getId());
    }

    @DisplayName("인증 후 원본 객체를 반환한다.")
    @Test
    void authenticate_returnsOriginalAuthentication() {
        // given
        User user = userRepository.save(new User("adminuser", UserRole.ADMIN));
        CustomJwtAuthentication original = new CustomJwtAuthentication(
                user.getId(),
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        // when
        Authentication result = provider.authenticate(original);

        // then
        Assertions.assertThat(result).isSameAs(original);
    }

    @DisplayName("존재하지 않는 사용자 -> 예외")
    @Test
    void authenticate_nonexistentUser_throwsException() {
        // given
        Long nonexistentUserId = 999L;
        Authentication authentication = new CustomJwtAuthentication(
                nonexistentUserId,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // when & then
        Assertions.assertThatThrownBy(() -> provider.authenticate(authentication))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("DB에 유저를 찾을 수 없습니다");
    }

    @DisplayName("인증이 잘 끝나고 -> authenticated가 true")
    @Test
    void authenticate_success_isAuthenticated() {
        // given
        User user = userRepository.save(new User("testuser", UserRole.USER));
        Authentication authentication = new CustomJwtAuthentication(
                user.getId(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // when
        Authentication result = provider.authenticate(authentication);

        // then
        Assertions.assertThat(result.isAuthenticated()).isTrue();
    }

    @DisplayName("지원하는 인증 타입을 확인한다 - CustomJwtAuthentication -> true")
    @Test
    void supports_customJwtAuthentication_returnsTrue() {
        // when
        boolean result = provider.supports(CustomJwtAuthentication.class);

        // then
        Assertions.assertThat(result).isTrue();
    }

    @DisplayName("지원하는 인증 타입을 확인한다 - 다른 타입 -> false")
    @Test
    void supports_otherAuthenticationType_returnsFalse() {
        // when
        boolean result = provider.supports(Authentication.class);

        // then
        Assertions.assertThat(result).isFalse();
    }
}


