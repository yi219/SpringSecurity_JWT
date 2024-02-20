package com.example.security.config.auth;

import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// SecurityConfig의 loginProcessingUrl("/login")
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수 실행
// username에 대한 User가 존재하면 loadByUsername 리턴값이
// -> Authentication에 UserDetails로 들어감
// -> Security Session에 Authentication으로 들어감
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 생성됨
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 해당 username이 존재하는지 확인
        User userEntity = userRepository.findByUsername(username);

        if(userEntity != null){
            // ===== Authentication에 저장
            return new PrincipalDetails(userEntity);
        }

        return null;
    }
}

