package chanllenge.spring_security.app.controller;


import chanllenge.spring_security.app.domain.UserService;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<Void> register(@RequestBody UserCreateRequest request) {
        userService.registerUser(request.username(), request.role());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    public record UserCreateRequest(
            String username,
            String password,
            String role
    ) { }

    @GetMapping("/me")
    public Map<String, Object> currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", authentication.isAuthenticated());
        response.put("principal", authentication.getPrincipal());
        response.put("authorities", authentication.getAuthorities());

        return response;
    }
    /**
     * 인증된 사용자만 접근 가능
     */
    @GetMapping("/protected")
    public Map<String, Object> protectedResource() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "인증된 유저만 호출 가능");
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }

}
