package chanllenge.spring_security.authentication.filter;

import chanllenge.spring_security.authentication.architecture.AuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.AuthenticationManager;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import chanllenge.spring_security.authentication.exception.AuthenticationException;
import chanllenge.spring_security.authentication.exception.InvalidTokenException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public JwtAuthenticationFilter(
            AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
    }

    @Override
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }

        String token = header.substring(7);
        try {
            Long userId = parseUserId(token);

            return new CustomJwtAuthentication(
                    userId,
                    List.of(new SimpleGrantedAuthority("ROLE_USER"))
            );
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("유효하지 않은 인증 토큰 포맷입니다.", e);
        }
    }

    private Long parseUserId(String token) {

        if (token.startsWith("user-")) {
            return Long.parseLong(token.substring(5));
        }
        throw new IllegalArgumentException();
    }
}
