package chanllenge.spring_security.authentication.context;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class CustomJwtAuthentication implements Authentication {
    private static final String ERROR_AUTHENTICATION_USERID_NULL ="UserId는 Null일 수 없습니다.";
    private static final String ERROR_AUTHENTICATION_AUTHORITY_NULL ="Authority는 Null일 수 없습니다.";
    private static final String ERROR_AUTHENTICATION_UNSUPPORTED_AUTHENTICATION = "이 토큰을 인증된 상태로 설정할 수 없습니다. 올바른 인증 방식을 사용해주세요.";

    private final Long userId;
    private final List<GrantedAuthority> authorities;
    private boolean authenticated = true;

    public CustomJwtAuthentication(Long userId, Collection<? extends GrantedAuthority> authorities) {
        if (userId == null) {
            throw new IllegalArgumentException(ERROR_AUTHENTICATION_USERID_NULL);
        }
        if (authorities == null) {
            throw new IllegalArgumentException(ERROR_AUTHENTICATION_AUTHORITY_NULL);
        }
        this.userId = userId;
        this.authorities = Collections.unmodifiableList(new ArrayList<>(authorities));
    }

    public Long getUserId() {
        return userId;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException(ERROR_AUTHENTICATION_UNSUPPORTED_AUTHENTICATION);
        }
        this.authenticated = false;
    }

    @Override
    public String getName() {
        return userId.toString();
    }
}
