package chanllenge.spring_security.app.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    private static final String ERROR_USER_NAME_BLANK = "유저이름은 널이거나 비어있을 수 없습니다.";
    private static final String ERROR_USER_PASSWORD_BLANK = "유저 비밀번호는 널이거나 비어있을 수 없습니다.";
    private static final String ERROR_USER_ROLE_BLANK = "유저 role은 널이거나 비어있을 수 없습니다.";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    private UserRole role;

    public User(String username, String password, UserRole role) {
        validateUsername(username);
        validatePassword(password);
        validateRole(role);

        this.username = username;
        this.password = password;
        this.role = role;
    }

    private void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException(ERROR_USER_NAME_BLANK);
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException(ERROR_USER_PASSWORD_BLANK);
        }
    }

    private void validateRole(UserRole role) {
        if (role == null) {
            throw new IllegalArgumentException(ERROR_USER_ROLE_BLANK);
        }
    }

}
