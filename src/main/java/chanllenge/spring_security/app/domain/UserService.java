package chanllenge.spring_security.app.domain;

import chanllenge.spring_security.authorization.architecture.method.annotation.PostAuthorize;
import chanllenge.spring_security.authorization.architecture.method.annotation.PreAuthorize;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String ERROR_USER_ALREADY_EXISTS = "이미 존재하는 사용자명입니다.";
    private static final String ERROR_USER_NOT_FOUND = "사용자를 찾을 수 없습니다.";

    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void registerUser(String username, String role) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException(ERROR_USER_ALREADY_EXISTS);
        }

        UserRole userRole = UserRole.from(role);
        User user = new User(username, userRole);
        userRepository.save(user);
    }

    @PreAuthorize("isAuthenticated()")
    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(ERROR_USER_NOT_FOUND));
    }

    @PostAuthorize("returnObject.id == authentication.principal")
    @Transactional(readOnly = true)
    public User getMyProfile(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(ERROR_USER_NOT_FOUND));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new IllegalArgumentException(ERROR_USER_NOT_FOUND);
        }
        userRepository.deleteById(userId);
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @Transactional
    public void deleteUserV2(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new IllegalArgumentException(ERROR_USER_NOT_FOUND);
        }
        userRepository.deleteById(userId);
    }

    @Transactional(readOnly = true)
    public User findById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException(ERROR_USER_NOT_FOUND));
    }
}
