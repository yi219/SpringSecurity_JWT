package com.example.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        System.out.println("filter 3");

        if(request.getMethod().equals("POST")){
            String headerAuth = request.getHeader("Authorization");
            System.out.println("headerAuth: ");
            System.out.println(headerAuth);

            if(headerAuth.equals("authorized")){
                filterChain.doFilter(request, response);
            }else{
                PrintWriter out = response.getWriter();
                out.println("인증 안됨");
            }
        }
    }
}
