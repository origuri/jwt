package com.cos.jwt.controller;

import com.cos.jwt.Entity.Member;
import com.cos.jwt.dto.MemberDto;
import com.cos.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final MemberRepository memberRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody MemberDto memberDto){
        memberDto.setPassword(bCryptPasswordEncoder.encode(memberDto.getPassword()));
        memberDto.setRole("ROLE_USER");
        Member member = Member.toJoinMemberEntity(memberDto);
        memberRepository.save(member);
        return "회원가입완료";
    }

    // user, mananger, admin 접근 가능
    @GetMapping("/api/v1/user")
    public String user(){
        return "user";
    }
    // manager, admin 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }
    // admin 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
