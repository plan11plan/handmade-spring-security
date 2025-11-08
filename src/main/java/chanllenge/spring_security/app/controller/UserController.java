package chanllenge.spring_security.app.controller;


import chanllenge.spring_security.app.domain.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    /**
     * 사용자를 생성하고 비밀번호를 암호화하여 저장하는 기능
     */
    @PostMapping
    public ResponseEntity<Void> register(@RequestBody UserCreateRequest request) {
        userService.registerUser(request.username(), request.password(), request.role());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * 저장된 사용자의 비밀번호를 검증하는 기능
     */
    @PostMapping("/verify-password")
    public ResponseEntity<PasswordVerifyResponse> verifyPassword(
            @RequestBody PasswordVerifyRequest request
    ) {
        boolean matches = userService.verifyPassword(request.username(), request.password());
        return ResponseEntity.ok(new PasswordVerifyResponse(matches));
    }

    public record UserCreateRequest(
            String username,
            String password,
            String role
    ) { }

    public record PasswordVerifyRequest(
            String username,
            String password
    ) { }

    public record PasswordVerifyResponse(
            boolean matches
    ) { }
}
