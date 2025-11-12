package chanllenge.spring_security.authorization.filter;

import chanllenge.spring_security.authentication.architecture.AuthenticationEntryPoint;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authentication.exception.AuthenticationException;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.exception.AccessDeniedHandler;
import chanllenge.spring_security.authorization.exception.AuthorizationDeniedException;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.GenericFilterBean;

public class AuthorizationFilter extends GenericFilterBean {

    private final AuthorizationManager<String> authorizationManager;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final AccessDeniedHandler accessDeniedHandler;

    public AuthorizationFilter(
            AuthorizationManager<String> authorizationManager,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler
    ) {
        this.authorizationManager = authorizationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String requestUri = request.getRequestURI();
        AuthorizationResult result = authorizationManager.authorize(() -> authentication, requestUri);

        if (result != null && !result.isGranted()) {
            handleAccessDeniedException(request, response, authentication);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void handleAccessDeniedException(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (isAnonymous(authentication)) {
            authenticationEntryPoint.commence(request, response, new AuthenticationException("인증되지 않은 사용자입니다."));
            return;
        }
        accessDeniedHandler.handle(request, response, new AuthorizationDeniedException("접근을 위한 권한이 없습니다."));
    }

    private boolean isAnonymous(Authentication authentication) {
        return authentication == null;
    }
}
