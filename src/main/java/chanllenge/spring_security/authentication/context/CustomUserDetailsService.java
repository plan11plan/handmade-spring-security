package chanllenge.spring_security.authentication.context;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserRepository;
import chanllenge.spring_security.authentication.exception.UserNotFoundException;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private static final String ERROR_USER_NOTFOUND = "DB에 유저를 찾을 수 없습니다.";
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserById(Long id) throws UserNotFoundException {
        User entityUser = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(ERROR_USER_NOTFOUND + id));

        return new CustomUserDetails(
                entityUser.getUsername(),
                Collections.singletonList(new SimpleGrantedAuthority(entityUser.getRole().toString()))
        );
    }

}
