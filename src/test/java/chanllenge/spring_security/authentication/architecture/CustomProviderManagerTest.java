package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.app.domain.UserRole;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import java.util.Collections;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
class CustomProviderManagerTest {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserRepository userRepository;

    private CustomJwtAuthenticationProvider jwtProvider;

    @BeforeEach
    void setUp() {
        jwtProvider = new CustomJwtAuthenticationProvider(userDetailsService);
    }

    @DisplayName("빈 Provider 목록 -> 예외")
    @Test
    void manageProviders_emptyList_throwsException() {
        // expect
        Assertions.assertThatThrownBy(() -> new CustomProviderManager(Collections.emptyList()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Provider 목록은 비어있을 수 없습니다");
    }

    @DisplayName("null Provider 목록 -> 예외")
    @Test
    void manageProviders_nullList_throwsException() {
        // expect
        Assertions.assertThatThrownBy(() -> new CustomProviderManager(null))
                .isInstanceOf(Exception.class);
    }


    @DisplayName("지원 가능한 Provider 존재 -> 해당 Provider 사용")
    @Test
    void delegateAuthentication_supportingProviderExists() {
        // given
        CustomProviderManager customProviderManager = new CustomProviderManager(List.of(jwtProvider));
        User user = userRepository.save(new User("testuser", UserRole.USER));
        Authentication authentication = new CustomJwtAuthentication(
                user.getId(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // when
        Authentication result = customProviderManager.authenticate(authentication);

        // then
        Assertions.assertThat(result.isAuthenticated()).isTrue();
        Assertions.assertThat(result).isInstanceOf(CustomJwtAuthentication.class);
    }

    @DisplayName("지원 가능한 Provider 없음 -> 예외")
    @Test
    void delegateAuthentication_noSupportingProvider_Exception() {
        // given
        CustomProviderManager customProviderManager = new CustomProviderManager(List.of(jwtProvider));
        Authentication unsupportedAuth = new Authentication() {
            @Override
            public Object getPrincipal() { return "test"; }
            @Override
            public Object getCredentials() { return "test"; }
            @Override
            public java.util.Collection<? extends chanllenge.spring_security.authentication.context.GrantedAuthority> getAuthorities() {
                return Collections.emptyList();
            }
            @Override
            public boolean isAuthenticated() { return false; }
            @Override
            public void setAuthenticated(boolean isAuthenticated) {}
            @Override
            public String getName() { return "test"; }
        };

        // expect
        Assertions.assertThatThrownBy(() -> customProviderManager.authenticate(unsupportedAuth))
                .isInstanceOf(ProviderNotFoundException.class);
    }
}
