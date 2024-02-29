package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// Spring Security의 필터 중 "AuthenticationFilter"
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 거침
// 권한이나 인증이 필요햔 주소가 아니라면 위 필터를 거치지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);

        // JWT Token을 검증하여 정상적인 사용자인지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC512("secretKEY"))
                .build()
                .verify(token)
                .getClaim("username")
                .asString();

        if (username != null){
            User userEntity = userRepository.findByUsername(username);
            System.out.println(userEntity);

            // 실제로 로그인한 것이 아닌, 서명을 통해 검증하여 Authentication을 생성
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 시큐리티 세션에 접근하여 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}
