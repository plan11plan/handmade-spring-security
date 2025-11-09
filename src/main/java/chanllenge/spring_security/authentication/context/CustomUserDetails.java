package chanllenge.spring_security.authentication.context;

import java.util.Collections;
import java.util.List;
import org.springframework.util.Assert;

public class CustomUserDetails implements UserDetails {
    private String password;

    private final String username;

    private final List<GrantedAuthority> authorities;

    public CustomUserDetails(String username, String password, List<GrantedAuthority> authorities) {
        Assert.isTrue(
                username != null && !"".equals(username) && password != null,
                "생성자에 null이나 빈값을 넣을 수 없습니다.");
        this.username = username;
        this.password = password;
        this.authorities = Collections.unmodifiableList(authorities);
    }

    @Override
    public List<GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

}
