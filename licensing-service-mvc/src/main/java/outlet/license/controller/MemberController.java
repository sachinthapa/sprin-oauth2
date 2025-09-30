package outlet.license.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/member")
public class MemberController {

    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public String welcome() {
        return "memberList";
    }

    @GetMapping(value = "/add", produces = "text/plain")
    @ResponseBody
    public String addMember() {
        return "memberList";
    }

    @RequestMapping(path = {"/remove", "/delete"}, method = RequestMethod.GET)
    public String removeMember(@RequestParam("memberName") String memberName) {
        return "redirect:";
    }

    @RequestMapping("/display/{member}")
    public String displayMember(@PathVariable("member") String member, Model model) {
        model.addAttribute("member");
        return "member";
    }
}
