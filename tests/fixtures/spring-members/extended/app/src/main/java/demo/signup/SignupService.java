package demo.signup;

import org.springframework.stereotype.Service;

@Service
public class SignupService {

    private final SignupMapper signupMapper;

    public SignupService(SignupMapper signupMapper) {
        this.signupMapper = signupMapper;
    }

    public void register(String name) {
        signupMapper.insertMember(name);
    }

    public void complete(String verificationId) {
        signupMapper.markVerified(verificationId);
    }
}
