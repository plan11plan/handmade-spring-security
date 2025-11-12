package chanllenge.spring_security.authentication.architecture;


import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import chanllenge.spring_security.authentication.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomJwtAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomJwtAuthentication jwtAuthentication = (CustomJwtAuthentication) authentication;
        Long userId = jwtAuthentication.getUserId();

        // 존재하지 않으면 UsernameNotFoundException 발생
        userDetailsService.loadUserById(userId);

        // CustomJwtAuthentication은 생성 시점에 이미 authenticated=true여서 원본 객체를 그대로 반환
        return jwtAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomJwtAuthentication.class.isAssignableFrom(authentication);
    }
}
