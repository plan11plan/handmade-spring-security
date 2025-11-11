package chanllenge.spring_security.authorization.model;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CustomAuthorizationDecisionTest {


    @Test
    @DisplayName("결정 결과를 조회한다 - true")
    void authorizationDecision_is_granted_true() {
        // given
        chanllenge.spring_security.authorization.model.AuthorizationResult decision = new CustomAuthorizationDecision(true);

        // when
        boolean result = decision.isGranted();

        // then
        Assertions.assertThat(result).isTrue();
    }

    @Test
    @DisplayName("결정 결과를 조회한다 - false")
    void authorizationDecision_is_granted_false() {
        // given
        chanllenge.spring_security.authorization.model.AuthorizationResult decision = new CustomAuthorizationDecision(false);

        // when
        boolean result = decision.isGranted();

        // then
        Assertions.assertThat(result).isFalse();
    }

}
