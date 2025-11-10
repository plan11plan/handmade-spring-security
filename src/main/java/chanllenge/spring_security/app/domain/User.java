package chanllenge.spring_security.app.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

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


    @Enumerated(EnumType.STRING)
    private UserRole role;

    public User(String username, UserRole role) {
        validateUsername(username);
        validateRole(role);

        this.username = username;
        this.role = role;
    }

    private void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException(ERROR_USER_NAME_BLANK);
        }
    }

    private void validateRole(UserRole role) {
        if (role == null) {
            throw new IllegalArgumentException(ERROR_USER_ROLE_BLANK);
        }
    }

}
