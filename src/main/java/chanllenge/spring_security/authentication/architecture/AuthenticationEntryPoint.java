package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.authentication.exception.AuthenticationException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface AuthenticationEntryPoint {

    void commence(HttpServletRequest request,
                  HttpServletResponse response,
                  AuthenticationException authException)
        throws IOException, ServletException;
}
