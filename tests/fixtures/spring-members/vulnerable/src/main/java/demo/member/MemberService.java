package demo.member;

import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class MemberService {

    private final MemberMapper memberMapper;

    public MemberService(MemberMapper memberMapper) {
        this.memberMapper = memberMapper;
    }

    public List<MemberMapper.Member> list() {
        return memberMapper.findAll();
    }

    public void suspend(long id) {
        memberMapper.updateStatus(id, "SUSPENDED");
    }

    public void delete(long id) {
        memberMapper.deleteById(id);
    }
}
