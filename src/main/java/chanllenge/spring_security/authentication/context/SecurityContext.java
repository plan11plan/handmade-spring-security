package chanllenge.spring_security.authentication.context;

public interface SecurityContext {

    void setAuthentication(Authentication authentication);

    Authentication getAuthentication();
}
