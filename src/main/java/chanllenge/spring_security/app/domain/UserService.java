package chanllenge.spring_security.app.domain;

import chanllenge.spring_security.app.infrastructure.crypto.PasswordEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String ERROR_USER_ALREADY_EXISTS = "이미 존재하는 사용자명입니다.";
    private static final String ERROR_USER_NOT_FOUND = "사용자를 찾을 수 없습니다.";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 사용자를 생성하고 저장하는 기능
     */
    @Transactional
    public void registerUser(String username, String role) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException(ERROR_USER_ALREADY_EXISTS);
        }

        UserRole userRole = UserRole.from(role);
        User user = new User(username, userRole);
        userRepository.save(user);
    }
}
