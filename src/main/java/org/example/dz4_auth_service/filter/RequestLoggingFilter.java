package org.example.dz4_auth_service.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.stream.Collectors;

public class RequestLoggingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("=== INCOMING REQUEST ===");
        System.out.println("URL: " + request.getRequestURL());
        System.out.println("Headers: " + Collections.list(request.getHeaderNames())
                .stream()
                .map(name -> name + ": " + request.getHeader(name))
                .collect(Collectors.joining(", ")));

        filterChain.doFilter(request, response);
    }
}
