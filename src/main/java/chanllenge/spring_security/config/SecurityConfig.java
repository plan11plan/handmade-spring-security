package chanllenge.spring_security.config;

import chanllenge.spring_security.authentication.architecture.AuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.AuthenticationManager;
import chanllenge.spring_security.authentication.architecture.CustomAuthenticationEntryPoint;
import chanllenge.spring_security.authentication.architecture.CustomJwtAuthenticationProvider;
import chanllenge.spring_security.authentication.architecture.CustomProviderManager;
import chanllenge.spring_security.authentication.context.UserDetailsService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

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

}
