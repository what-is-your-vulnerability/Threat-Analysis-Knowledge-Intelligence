package demo.signup;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/signup")
public class SignupController {

    private final SignupService signupService;

    public SignupController(SignupService signupService) {
        this.signupService = signupService;
    }

    @PostMapping
    public void signup(@RequestParam String name) {
        signupService.register(name);
    }

    @PostMapping("/verifications/{verificationId}/complete")
    public void completeVerification(@PathVariable String verificationId) {
        signupService.complete(verificationId);
    }
}
