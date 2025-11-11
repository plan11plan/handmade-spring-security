package chanllenge.spring_security.authorization.model;

public class CustomAuthorizationDecision implements AuthorizationResult {

    private final boolean granted;

    public CustomAuthorizationDecision(boolean granted) {
        this.granted = granted;
    }

    @Override
    public boolean isGranted() {
        return this.granted;
    }

}
