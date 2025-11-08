package chanllenge.spring_security.app.infrastructure.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BCryptPasswordEncoderTest {
    private PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        encoder = new BCryptPasswordEncoder();
    }

    @Test
    @DisplayName("비밀번호를 암호화한다")
    void encodePassword() {
        // given
        String rawPassword = "password123";

        // when
        String encoded = encoder.encode(rawPassword);

        // then
        assertThat(encoded).isNotNull();
        assertThat(encoded).startsWith("$2a$10$");
        assertThat(encoded).isNotEqualTo(rawPassword);
    }

    @Test
    @DisplayName("같은 비밀번호라도 매번 다른 해시를 생성한다")
    void encodeSamePasswordMultipleTimes() {
        // given
        String rawPassword = "password123";

        // when
        String encoded1 = encoder.encode(rawPassword);
        String encoded2 = encoder.encode(rawPassword);

        // then
        assertThat(encoded1).isNotEqualTo(encoded2);
    }

}
