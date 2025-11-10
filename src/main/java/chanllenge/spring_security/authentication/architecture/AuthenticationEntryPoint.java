package chanllenge.spring_security.authentication.architecture;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;

public interface AuthenticationEntryPoint {

    void commence(HttpServletRequest request,
                  HttpServletResponse response,
                  AuthenticationException authException)
        throws IOException, ServletException;
}
