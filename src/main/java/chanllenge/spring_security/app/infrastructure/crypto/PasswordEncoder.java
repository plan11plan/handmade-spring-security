package chanllenge.spring_security.app.infrastructure.crypto;

public interface PasswordEncoder {
    String encode(String rawPassword);
    boolean matches(String rawPassword, String encodedPassword);
}
