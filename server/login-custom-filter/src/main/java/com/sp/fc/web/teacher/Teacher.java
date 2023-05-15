package com.sp.fc.web.teacher;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Teacher {
    private String id;
    private String username;
    private Set<GrantedAuthority> role;
}
