package com.cos.jwt.Entity;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member {

    @Id @GeneratedValue
    private Long id;

    private String username;

    private String password;

    private String roles; // USER, ADIMN

    /*
    *  권한을 가져오는 함수
    *  굳이 이렇게 쓰는 이유는 나중에 확인해봐야 할듯.
    *
    * */
    public List<String> getRoleList(){
        if(this.roles.length()>0){
            return Arrays.asList(this.roles.split(","));
        } else {
            return new ArrayList<>();
        }

    }
}
