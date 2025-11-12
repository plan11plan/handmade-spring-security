package chanllenge.spring_security.authentication.architecture;


import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.UserDetails;
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

        // 사용자 존재 여부 확인 및 실제 권한 정보 로드
        UserDetails userDetails = userDetailsService.loadUserById(userId);

        // 실제 DB의 권한으로 새로운 인증 객체 생성
        return new CustomJwtAuthentication(userId, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomJwtAuthentication.class.isAssignableFrom(authentication);
    }
}
