package demo.me;

import java.security.Principal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

    @GetMapping("/api/v1/me/profile")
    public String profile(Principal principal) {
        return principal.getName();
    }
}
