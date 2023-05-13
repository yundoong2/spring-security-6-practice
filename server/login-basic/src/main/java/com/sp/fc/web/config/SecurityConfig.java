package com.sp.fc.web.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthDetails customAuthDetails;

    /**
     * 비밀번호 암호화 Encoder
     * @author cyh68
     * @since 2023-05-12
     **/
    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 관리자가 일반 USER_ROLE 의 페이지도 접속 가능하도록 설정
     * @author cyh68
     * @since 2023-05-12
     **/
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_SUPERUSER > ROLE_USER");
        return roleHierarchy;
    }

    /**
     * 접속 계정 등록
     * @author cyh68
     * @since 2023-05-12
     **/
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder()
                .username("user1")
//                .password("1111")
                .password(passwordEncoder().encode("1111"))
                .roles("USER")
                .build();

        UserDetails user2 = User.builder()
                .username("admin")
//                .password("2222")
                .password(passwordEncoder().encode("2222"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, user2);
    }

    /**
     * 접속 Page 와 권한 관련된 설정
     * @author cyh68
     * @since 2023-05-12
     **/
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        http.authorizeHttpRequests()
                .requestMatchers("/").permitAll()
                .anyRequest().authenticated();

        //권한 없는 페이지 접속 시, 기본 로그인 페이지로 redirect 됨
        //formLogin()안에 특정 페이지를 지정해주면 해당 페이지로 redirect 됨
        http.formLogin(
                        login -> login.loginPage("/login")
                                .permitAll()
                                //로그인 성공 후, 이동시킬 기본 페이지.
                                //alwaysUse를 true로 해놓으면 로그인후 무조건 기본 페이지로 이동하므로 false 를 사용하자
                                .defaultSuccessUrl("/", false)
                                //로그인 실패 시, 이동시킬 페이지
                                .failureUrl("/login-error")
                                .authenticationDetailsSource(customAuthDetails)
                )
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"))
        ;


        return http.build();
    }


    /**
     * 권한 관련 추가 설정
     * @author cyh68
     * @since 2023-05-12
     **/
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //static 리소스는 Spring security가 적용되지 않도록 ignoring에 추가
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

}
