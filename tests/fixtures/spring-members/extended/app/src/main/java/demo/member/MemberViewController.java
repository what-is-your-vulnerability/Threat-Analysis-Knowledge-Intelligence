package demo.member;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin/members")
public class MemberViewController {

    private final MemberDetailMapper memberDetailMapper;

    public MemberViewController(MemberDetailMapper memberDetailMapper) {
        this.memberDetailMapper = memberDetailMapper;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String detail(@PathVariable long id, Model model) {
        model.addAttribute("member", memberDetailMapper.findById(id));
        return "admin/member-detail";
    }
}
