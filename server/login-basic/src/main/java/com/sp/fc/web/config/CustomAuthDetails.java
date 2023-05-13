package com.sp.fc.web.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class CustomAuthDetails implements AuthenticationDetailsSource<HttpServletRequest, RequestInfo> {

    @Override
    public RequestInfo buildDetails(HttpServletRequest request) {
        return RequestInfo.builder()
                .remoteIp(request.getRemoteAddr())
                .sessionId(request.getSession().getId())
                .loginTime(LocalDateTime.now())
                .build();
    }
}
