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
     * 사용자를 생성하여 저장하는 기능
     */
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

}
