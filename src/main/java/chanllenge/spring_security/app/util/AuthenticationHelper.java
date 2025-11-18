package chanllenge.spring_security.app.util;

import chanllenge.spring_security.authentication.context.CustomJwtAuthentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import chanllenge.spring_security.authentication.context.SimpleGrantedAuthority;
import java.util.List;

public class AuthenticationHelper {

    public static void authenticateAsUser(Long userId) {
        CustomJwtAuthentication auth = new CustomJwtAuthentication(
                userId,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    public static void authenticateAsAdmin(Long userId) {
        CustomJwtAuthentication auth = new CustomJwtAuthentication(
                userId,
                List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                )
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    public static void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }
}
