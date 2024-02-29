package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

// Spring Security에 존재하는 UsernamePasswordAuthenticationFilter
// 로그인 요청에 username, password룰 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함
// SecurityConfig에서 formLogin을 disable시키면 동작하지 않음
// -> 다시 동작하도록 필터를 등록해줘야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

   private final AuthenticationManager authenticationManager;

   // /login 요청 시 로그인 시도를 위해 실행되는 함수
   // authenticationManager로 로그인 시도
   // -> PrincipalDetailsService가 호출됨!!
   // -> PrincipalDetailsService의 loadByUsername() 함수 실행
   // -> PrincipalDetails를 세션에 담고 (편리한 권한 관리를 위해. 권한 분류 없이 JWT를 사용하면 굳이 세션 생성할 필요 X)
   // -> JWT 토큰을 생성하여 응답
   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
       try {
          ObjectMapper om = new ObjectMapper();
          User user = om.readValue(request.getInputStream(), User.class);

           UsernamePasswordAuthenticationToken authenticationToken =
                   new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

           // PrincipalDetailsService의 loadUserByUsername() 실행
           // 로그인 성공 시 authentication에 로그인 정보가 담김
           Authentication authentication = authenticationManager.authenticate(authenticationToken);

           PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
           System.out.println(principalDetails.getUser());

           // authentication 객체를 session 영역에 저장
           return authentication;

       } catch (IOException e) {
           throw new RuntimeException(e);
       }
   }

    // attemptAuthentication에서 정상적으로 인증된다면 실행되는 함수
    // JWT 토큰 생성 후 전달
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("Token")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("secretKEY"));

        response.addHeader("Authorization", "Bearer "+jwtToken);

//        super.successfulAuthentication(request, response, chain, authResult);
    }
}
