package chanllenge.spring_security.authentication.architecture;

import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.exception.AuthenticationException;
import java.util.Collections;
import java.util.List;

/**
 * 여러 AuthenticationProvider를 관리하는 AuthenticationManager 구현체
 *
 * 책임:
 * - Provider 목록 관리
 * - 적절한 Provider 선택 및 인증 위임
 * - 인증 실패 처리
 */
public class CustomProviderManager implements AuthenticationManager {
    private static final String ERROR_NULL_PROVIDERS = "Provider 목록은 null일 수 없습니다";
    private static final String ERROR_EMPTY_PROVIDERS = "Provider 목록은 비어있을 수 없습니다";
    private static final String ERROR_NULL_AUTHENTICATION = "Authentication은 null일 수 없습니다";
    private static final String ERROR_NO_PROVIDER_FOUND = "인증을 처리할 수 있는 Provider를 찾을 수 없습니다";

    private final List<AuthenticationProvider> providers;

    public CustomProviderManager(List<AuthenticationProvider> providers) {
        validateProviders(providers);
        this.providers = Collections.unmodifiableList(providers);
    }

    private void validateProviders(List<AuthenticationProvider> providers) {
        if (providers == null) {
            throw new IllegalArgumentException(ERROR_NULL_PROVIDERS);
        }
        if (providers.isEmpty()) {
            throw new IllegalArgumentException(ERROR_EMPTY_PROVIDERS);
        }
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            throw new IllegalArgumentException(ERROR_NULL_AUTHENTICATION);
        }

        Class<? extends Authentication> toTest = authentication.getClass();

        for (AuthenticationProvider provider : providers) {
            if (provider.supports(toTest)) {
                return provider.authenticate(authentication);
            }
        }

        throw new ProviderNotFoundException(
                ERROR_NO_PROVIDER_FOUND + ": " + toTest.getName()
        );
    }
}
