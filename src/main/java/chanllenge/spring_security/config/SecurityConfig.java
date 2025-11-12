package chanllenge.spring_security.config;

import chanllenge.spring_security.authentication.architecture.AuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.AuthenticationManager;
import chanllenge.spring_security.authentication.architecture.CustomAuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.CustomJwtAuthenticationProvider;
import chanllenge.spring_security.authentication.architecture.CustomProviderManager;
import chanllenge.spring_security.authentication.filter.JwtAuthenticationFilter;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import chanllenge.spring_security.authorization.architecture.AuthorizationManager;
import chanllenge.spring_security.authorization.architecture.request.RequestMatcherDelegatingAuthorizationManager;
import chanllenge.spring_security.authorization.exception.AccessDeniedHandler;
import chanllenge.spring_security.authorization.filter.AuthorizationFilter;
import chanllenge.spring_security.authorization.util.AntPathRequestMatcher;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final AccessDeniedHandler accessDeniedHandler;

    @Bean
    public CustomJwtAuthenticationProvider customJwtAuthenticationProvider() {
        return new CustomJwtAuthenticationProvider(userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new CustomProviderManager(List.of(customJwtAuthenticationProvider()));
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }

    @Bean
    public AuthorizationManager<String> authorizationManager() {
        return RequestMatcherDelegatingAuthorizationManager.builder()
                .requestMatchers(new AntPathRequestMatcher("/api/admin/**"))
                .hasRole("ADMIN")
                .requestMatchers(new AntPathRequestMatcher("/api/users/**"))
                .authenticated()
                .anyRequest()
                .permitAll()
                .build();
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilter() {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(
                authenticationManager(),
                authenticationEntryPoint()
        );

        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/api/*", "/api/**");
        registrationBean.setOrder(1);

        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<AuthorizationFilter> authorizationFilter() {
        AuthorizationFilter filter = new AuthorizationFilter(
                authorizationManager(),
                authenticationEntryPoint(),
                accessDeniedHandler
        );

        FilterRegistrationBean<AuthorizationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/api/*", "/api/**");
        registrationBean.setOrder(2);

        return registrationBean;
    }
}
