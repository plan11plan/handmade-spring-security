package chanllenge.spring_security.app.controller;

import chanllenge.spring_security.app.domain.User;
import chanllenge.spring_security.app.domain.UserService;
import chanllenge.spring_security.app.util.AuthenticationHelper;
import chanllenge.spring_security.authentication.context.Authentication;
import chanllenge.spring_security.authentication.context.SecurityContextHolder;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    private void setupAuthentication(String userId, String role) {
        log.info("setupAuthentication called - userId: {}, role: {}", userId, role);
        if (userId != null) {
            Long id = Long.parseLong(userId);
            if ("ADMIN".equalsIgnoreCase(role)) {
                AuthenticationHelper.authenticateAsAdmin(id);
                log.info("Authenticated as ADMIN: {}", id);
            } else {
                AuthenticationHelper.authenticateAsUser(id);
                log.info("Authenticated as USER: {}", id);
            }
        } else {
            log.warn("userId가 null입니다. - no authentication setup");
        }
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody UserCreateRequest request) {
        userService.registerUser(request.username(), request.role());

        Map<String, Object> response = new HashMap<>();
        response.put("message", "사용자 생성 성공");
        response.put("username", request.username());
        response.put("role", request.role());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    public record UserCreateRequest(String username, String role) { }

    @GetMapping("/me")
    public Map<String, Object> currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", authentication.isAuthenticated());
        response.put("principal", authentication.getPrincipal());
        response.put("authorities", authentication.getAuthorities());

        return response;
    }

    @GetMapping("/protected")
    public Map<String, Object> protectedResource() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "인증된 유저만 호출 가능");
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }

    @GetMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(
            @PathVariable Long userId,
            @RequestHeader(value = "X-User-Id", required = false) String authUserId,
            @RequestHeader(value = "X-User-Role", required = false) String authUserRole) {
        log.info("getUser called- pathVariable: {}, authUserId: {}, authUserRole: {}", userId, authUserId, authUserRole);
        setupAuthentication(authUserId, authUserRole);

        User user = userService.getUserById(userId);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("role", user.getRole().name());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/{userId}/profile")
    public ResponseEntity<Map<String, Object>> getMyProfile(
            @PathVariable Long userId,
            @RequestHeader(value = "X-User-Id", required = false) String authUserId,
            @RequestHeader(value = "X-User-Role", required = false) String authUserRole) {
        setupAuthentication(authUserId, authUserRole);

        User user = userService.getMyProfile(userId);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("role", user.getRole().name());
        response.put("message", "본인 프로필 조회 성공");

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, String>> deleteUser(
            @PathVariable Long userId,
            @RequestHeader(value = "X-User-Id", required = false) String authUserId,
            @RequestHeader(value = "X-User-Role", required = false) String authUserRole) {
        setupAuthentication(authUserId, authUserRole);

        userService.deleteUser(userId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "사용자 삭제 완료");
        response.put("deletedUserId", userId.toString());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/{userId}/public")
    public ResponseEntity<Map<String, Object>> getUserPublic(@PathVariable Long userId) {
        User user = userService.findById(userId);

        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("role", user.getRole().name());
        response.put("message", "권한 검사 없음 - 누구나 접근 가능");

        return ResponseEntity.ok(response);
    }
}
