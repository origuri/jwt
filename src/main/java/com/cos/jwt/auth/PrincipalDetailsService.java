package com.cos.jwt.auth;

import com.cos.jwt.Entity.Member;
import com.cos.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    /*
    * /login 주소가 요청되면 실행됨.
    * */
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principalDetailsService의 loadUserByUsername()");
        Member memberEntity = memberRepository.findByUsername(username);
        return new PrincipalDetails(memberEntity);
    }
}
