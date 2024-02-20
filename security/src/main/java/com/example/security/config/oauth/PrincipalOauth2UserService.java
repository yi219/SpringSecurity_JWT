package com.example.security.config.oauth;

import com.example.security.config.auth.PrincipalDetails;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

// 구글 로그인 버튼
// > 구글 로그인 완료
// > 코드 리턴 -> OAuth-Client 라이브러리가 받음
// > OAuth-Client 라이브러리가 코드를 통해 AccessToken 요청
// > userRequest 정보
// > loadUser(userRequest)로 회원 프로필 받기
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 생성됨
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        System.out.println("userRequest: " + userRequest);

        // registrationId => 어떤 OAuth로 로그인했는지 확인 가능
        System.out.println("userRequest.getClientRegistration: " + userRequest.getClientRegistration());
        System.out.println("userRequest.getAccessToken: " + userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("getAttributes: " + oAuth2User.getAttributes());

        // OAuth2 로그인 시 username과 password는 필요 없지만 일단 넣어줌!
        String provider = userRequest.getClientRegistration().getClientId();    // google
        String providerId = oAuth2User.getAttribute("sub"); // 클라이언트별 고유한 google 번호
        String username = provider + "_" + providerId;  // google_~~~~~~~~~~~ => 중복 X
        String password = bCryptPasswordEncoder.encode("히히");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId).build();
            userRepository.save(userEntity);
        }

        // ===== Authentication에 저장
        // return super.loadUser(userRequest);
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
