package chanllenge.spring_security.app.domain;

import java.util.Arrays;

public enum UserRole {
    USER,
    MANAGER,
    ADMIN;

    private static final String ERROR_ROLE_BLANK = "권한 문자열은 null이거나 비어 있을 수 없습니다.";
    private static final String ERROR_ROLE_INVALID = "지원하지 않는 권한입니다: ";

    public static UserRole from(String role) {
        if (role == null || role.isBlank()) {
            throw new IllegalArgumentException(ERROR_ROLE_BLANK);
        }

        return Arrays.stream(values())
                .filter(userRole -> userRole.name().equalsIgnoreCase(role.trim()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(ERROR_ROLE_INVALID + role));
    }
}
