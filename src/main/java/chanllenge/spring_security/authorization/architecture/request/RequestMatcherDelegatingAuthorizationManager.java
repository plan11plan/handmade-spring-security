package chanllenge.spring_security.authorization.architecture.request;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.model.AuthorizationResult;
import chanllenge.spring_security.authorization.model.CustomAuthorizationDecision;
import chanllenge.spring_security.authorization.util.AnyRequestMatcher;
import chanllenge.spring_security.authorization.util.RequestMatcher;
import chanllenge.spring_security.authorization.util.RequestMatcherEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.util.Assert;

public final class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<String> {

    private static final AuthorizationResult DENY = new CustomAuthorizationDecision(false);

    private static final String ERROR_MAPPINGS_EMPTY = "mappings는 비어있을 수 없습니다";

    private final List<RequestMatcherEntry<AuthorizationManager<String>>> mappings;

    private RequestMatcherDelegatingAuthorizationManager(List<RequestMatcherEntry<AuthorizationManager<String>>> mappings) {
        Assert.notEmpty(mappings, ERROR_MAPPINGS_EMPTY);
        this.mappings = new ArrayList<>(mappings);
    }

    @Override
    public AuthorizationResult authorize(Supplier<Authentication> authentication, String url) {
        for (RequestMatcherEntry<AuthorizationManager<String>> mapping : this.mappings) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            if (matcher.matches(url)) {
                AuthorizationManager<String> manager = mapping.getEntry();
                return manager.authorize(authentication, url);
            }
        }
        return DENY;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private static final String ERROR_ANY_REQUEST_ALREADY_CONFIGURED =
                "anyRequest()는 이미 설정되었습니다. anyRequest() 이후에는 추가 매핑을 설정할 수 없습니다";
        private static final String ERROR_ANY_REQUEST_DUPLICATE =
                "anyRequest()는 한 번만 호출할 수 있습니다";
        private static final String ERROR_REQUEST_MATCHERS_AFTER_ANY_REQUEST =
                "anyRequest() 이후에는 requestMatchers()를 설정할 수 없습니다";
        private static final String ERROR_MATCHER_NULL = "matcher는 null일 수 없습니다";
        private static final String ERROR_MANAGER_NULL = "manager는 null일 수 없습니다";
        private static final String ERROR_MATCHERS_EMPTY = "matchers는 비어있을 수 없습니다";
        private static final String ERROR_MATCHERS_CONTAIN_NULL = "matchers는 null 값을 포함할 수 없습니다";

        private boolean anyRequestConfigured;

        private final List<RequestMatcherEntry<AuthorizationManager<String>>> mappings = new ArrayList<>();

        public Builder add(RequestMatcher matcher, AuthorizationManager<String> manager) {
            Assert.state(!this.anyRequestConfigured, ERROR_ANY_REQUEST_ALREADY_CONFIGURED);
            Assert.notNull(matcher, ERROR_MATCHER_NULL);
            Assert.notNull(manager, ERROR_MANAGER_NULL);
            this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
            return this;
        }

        public AuthorizedUrl anyRequest() {
            Assert.state(!this.anyRequestConfigured, ERROR_ANY_REQUEST_DUPLICATE);
            this.anyRequestConfigured = true;
            return new AuthorizedUrl(AnyRequestMatcher.INSTANCE);
        }

        public AuthorizedUrl requestMatchers(RequestMatcher... matchers) {
            Assert.state(!this.anyRequestConfigured, ERROR_REQUEST_MATCHERS_AFTER_ANY_REQUEST);
            Assert.notEmpty(matchers, ERROR_MATCHERS_EMPTY);
            Assert.noNullElements(matchers, ERROR_MATCHERS_CONTAIN_NULL);
            return new AuthorizedUrl(matchers);
        }

        public RequestMatcherDelegatingAuthorizationManager build() {
            return new RequestMatcherDelegatingAuthorizationManager(this.mappings);
        }

        public final class AuthorizedUrl {

            private final List<RequestMatcher> matchers;

            private AuthorizedUrl(RequestMatcher... matchers) {
                this.matchers = List.of(matchers);
            }

            @SuppressWarnings("unchecked")
            public Builder permitAll() {
                return access((AuthorizationManager<String>) (AuthorizationManager<?>) new PermitAllAuthorizationManager());
            }

            @SuppressWarnings("unchecked")
            public Builder denyAll() {
                return access((AuthorizationManager<String>) (AuthorizationManager<?>) new DenyAllAuthorizationManager());
            }

            public Builder authenticated() {
                return access(AuthenticatedAuthorizationManager.authenticated());
            }

            public Builder hasRole(String role) {
                return access(AuthorityAuthorizationManager.hasRole(role));
            }

            public Builder hasAnyRole(String... roles) {
                return access(AuthorityAuthorizationManager.hasAnyRole(roles));
            }

            public Builder hasAuthority(String authority) {
                return access(AuthorityAuthorizationManager.hasAuthority(authority));
            }

            public Builder hasAnyAuthority(String... authorities) {
                return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
            }

            private Builder access(AuthorizationManager<String> manager) {
                for (RequestMatcher matcher : this.matchers) {
                    Builder.this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
                }
                return Builder.this;
            }
        }
    }

    @Override
    public String toString() {
        return "RequestMatcherDelegatingAuthorizationManager[mappings=" + this.mappings.size() + "]";
    }
}
