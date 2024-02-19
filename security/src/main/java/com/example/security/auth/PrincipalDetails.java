package com.example.security.auth;

import com.example.security.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

// /login 요청 시 시큐리티가 낚아채 로그인을 진행
// 로그인 진행이 완료되면 security session 생성
// Security Session <= Authentication <= UserDetails (PrincipalDetails)
public class PrincipalDetails implements UserDetails {

    private User user;

    private PrincipalDetails(User user){
        this.user = user;
    }

    // User 권한 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 1년 동안 회원이 로그인을 안 하면 휴면 계정으로 처리하는 경우
        // 현재 시간 - 로그인 시간 => 1년 초과 시 return false;

        return true;
    }
}
