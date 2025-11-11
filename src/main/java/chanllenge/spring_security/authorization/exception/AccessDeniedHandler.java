package chanllenge.spring_security.authorization.exception;// 경로 /security/exception/AccessDeniedHandler

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface AccessDeniedHandler {

    void handle(HttpServletRequest request, HttpServletResponse response, AuthorizationDeniedException exception)
            throws IOException, ServletException;
}
