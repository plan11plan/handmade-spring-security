package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContext;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authentication.exception.AuthenticationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;


public abstract class AbstractAuthenticationProcessingFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    protected AbstractAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            Authentication authRequest = attemptAuthentication(request, response);

            // 인증 정보 없으면 -> 다음 필터로 전달한다.
            if (authRequest == null) {
                filterChain.doFilter(request, response);
                return;
            }
            //
            Authentication authResult = authenticationManager.authenticate(authRequest);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);

            filterChain.doFilter(request, response);

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, e);
        }
    }

    protected abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException;
}
