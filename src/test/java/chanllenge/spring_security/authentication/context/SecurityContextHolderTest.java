package chanllenge.spring_security.authentication.context;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SecurityContextHolderTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @DisplayName("스레드별로 보안 컨텍스트를 관리한다.Get And Set")
    @Nested
    class EachThreadManageGetAndSet {
        @DisplayName("현재 스레드에 보안 컨텍스트 저장")
        @Test
        void setContext() {
            // given
            SecurityContext context = new SecurityContextImpl();

            // expect
            Assertions.assertThatCode(() -> SecurityContextHolder.setContext(context))
                    .doesNotThrowAnyException();
        }

        @DisplayName("null 컨텍스트 저장 -> 예외")
        @Test
        void setContext_null_exception() {
            // expect
            Assertions.assertThatThrownBy(() -> SecurityContextHolder.setContext(null))
                    .isInstanceOf(Exception.class);
        }

        @DisplayName("현재 스레드에서 보안 컨텍스트 조회")
        @Test
        void getContext() {
            // given
            Long userId = 1L;
            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
            Authentication auth = new CustomJwtAuthentication(userId, authorities);
            SecurityContext context = new SecurityContextImpl(auth);
            SecurityContextHolder.setContext(context);

            // when
            SecurityContext retrievedContext = SecurityContextHolder.getContext();

            // expect
            Assertions.assertThat(retrievedContext).isNotNull();
            Assertions.assertThat(retrievedContext).isEqualTo(context);
            Assertions.assertThat(retrievedContext.getAuthentication()).isEqualTo(auth);
        }

        @DisplayName("다른 스레드에서 조회 -> 새로운 빈 컨텍스트")
        @Test
        void getContext_different_thread_isolated() throws InterruptedException {
            // given: 현재 스레드에 컨텍스트 설정
            Long userId = 1L;
            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
            Authentication auth = new CustomJwtAuthentication(userId, authorities);
            SecurityContext context = new SecurityContextImpl(auth);
            SecurityContextHolder.setContext(context);

            // when: 다른 스레드에서 컨텍스트 조회
            AtomicReference<SecurityContext> otherThreadContext = new AtomicReference<>();
            CountDownLatch latch = new CountDownLatch(1);

            Thread otherThread = new Thread(() -> {
                otherThreadContext.set(SecurityContextHolder.getContext());
                latch.countDown();
            });
            otherThread.start();
            latch.await();

            // expect: 다른 스레드는 빈 컨텍스트를 가짐 (격리됨)
            SecurityContext currentThreadContext = SecurityContextHolder.getContext();
            Assertions.assertThat(currentThreadContext.getAuthentication()).isNotNull();
            Assertions.assertThat(otherThreadContext.get()).isNotNull();
            Assertions.assertThat(otherThreadContext.get().getAuthentication()).isNull();
        }
        @DisplayName("컨텍스트가 없으면 -> 새로운 빈 컨텍스트 생성")
        @Test
        void getContext_empty_creates_new() {
            // when
            SecurityContext context = SecurityContextHolder.getContext();

            // expect
            Assertions.assertThat(context).isNotNull();
            Assertions.assertThat(context.getAuthentication()).isNull();
        }

        @DisplayName("초기화 후 조회 -> 새로운 빈 컨텍스트")
        @Test
        void getContext_after_clear_new_empty() {
            // given
            Long userId = 1L;
            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
            Authentication auth = new CustomJwtAuthentication(userId, authorities);
            SecurityContext context = new SecurityContextImpl(auth);
            SecurityContextHolder.setContext(context);

            // when
            SecurityContextHolder.clearContext();
            SecurityContext newContext = SecurityContextHolder.getContext();

            // expect
            Assertions.assertThat(newContext).isNotNull();
            Assertions.assertThat(newContext).isNotEqualTo(context);
            Assertions.assertThat(newContext.getAuthentication()).isNull();
        }

    }


    @DisplayName("보안 컨텍스트를 초기화한다")
    @Test
    void clearContext() {
        // given
        Long userId = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth = new CustomJwtAuthentication(userId, authorities);
        SecurityContext context = new SecurityContextImpl(auth);
        SecurityContextHolder.setContext(context);

        // when
        SecurityContextHolder.clearContext();

        // expect
        SecurityContext newContext = SecurityContextHolder.getContext();
        Assertions.assertThat(newContext).isNotNull();
        Assertions.assertThat(newContext.getAuthentication()).isNull();
    }


    @DisplayName("스레드별로 독립적인 컨텍스트 관리")
    @Test
    void thread_isolation() throws InterruptedException {
        // given: 현재 스레드에 userId=1
        Long userId1 = 1L;
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
        Authentication auth1 = new CustomJwtAuthentication(userId1, authorities);
        SecurityContext context1 = new SecurityContextImpl(auth1);
        SecurityContextHolder.setContext(context1);

        // when: 다른 스레드에 userId=2
        AtomicReference<Authentication> otherThreadAuth = new AtomicReference<>();
        CountDownLatch latch = new CountDownLatch(1);

        Thread otherThread = new Thread(() -> {
            Long userId2 = 2L;
            Authentication auth2 = new CustomJwtAuthentication(userId2, authorities);
            SecurityContext context2 = new SecurityContextImpl(auth2);
            SecurityContextHolder.setContext(context2);
            otherThreadAuth.set(SecurityContextHolder.getContext().getAuthentication());
            latch.countDown();
        });
        otherThread.start();
        latch.await();

        // expect: 각 스레드는 각각 userId를 가짐
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        Assertions.assertThat(currentAuth).isNotNull();
        Assertions.assertThat(((CustomJwtAuthentication) currentAuth).getUserId()).isEqualTo(1L);
        Assertions.assertThat(otherThreadAuth.get()).isNotNull();
        Assertions.assertThat(((CustomJwtAuthentication) otherThreadAuth.get()).getUserId()).isEqualTo(2L);
    }

    @DisplayName("빈 컨텍스트 생성")
    @Test
    void createEmptyContext() {
        // when
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        // expect
        Assertions.assertThat(context).isNotNull();
        Assertions.assertThat(context.getAuthentication()).isNull();
    }
}
