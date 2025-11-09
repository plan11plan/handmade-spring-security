package chanllenge.spring_security.authentication.context;

import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SecurityContextTest {

    @DisplayName("인증 정보를 저장한다")
    @Test
    void setAuthentication() {
        // given
        SecurityContext context = new SecurityContextImpl();
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);

        // when
        context.setAuthentication(auth);

        // expect
        Assertions.assertThat(context.getAuthentication()).isNotNull();
        Assertions.assertThat(context.getAuthentication()).isEqualTo(auth);
    }

    @DisplayName("저장된 인증 정보 조회 가능")
    @Test
    void getAuthentication() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);
        SecurityContext context = new SecurityContextImpl(auth);

        // when
        Authentication result = context.getAuthentication();

        // expect
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result).isEqualTo(auth);
    }

    @DisplayName("빈 SecurityContext -> Authentication null")
    @Test
    void emptyContext_authentication_null() {
        // given
        SecurityContext context = new SecurityContextImpl();

        // expect
        Assertions.assertThat(context.getAuthentication()).isNull();
    }

    @DisplayName("인증 정보를 삭제한다 -> null 설정")
    @Test
    void clearAuthentication() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);
        SecurityContext context = new SecurityContextImpl(auth);

        // when
        context.setAuthentication(null);

        // expect
        Assertions.assertThat(context.getAuthentication()).isNull();
    }

    @DisplayName("삭제 후 조회 -> null")
    @Test
    void getAuthentication_after_clear_null() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);
        SecurityContext context = new SecurityContextImpl(auth);

        // when
        context.setAuthentication(null);
        Authentication result = context.getAuthentication();

        // expect
        Assertions.assertThat(result).isNull();
    }

    @DisplayName("Authentication 같다 -> equeals true")
    @Test
    void equals_same_authentication() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);
        SecurityContext context1 = new SecurityContextImpl(auth);
        SecurityContext context2 = new SecurityContextImpl(auth);

        // expect
        Assertions.assertThat(context1).isEqualTo(context2);
    }

    @DisplayName("Authentication 다르다 -> equals false")
    @Test
    void equals_different_authentication() {
        // given
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth1 = new CustomJwtAuthentication(1L, authorities);
        Authentication auth2 = new CustomJwtAuthentication(2L, authorities);
        SecurityContext context1 = new SecurityContextImpl(auth1);
        SecurityContext context2 = new SecurityContextImpl(auth2);

        // expect
        Assertions.assertThat(context1).isNotEqualTo(context2);
    }
}
