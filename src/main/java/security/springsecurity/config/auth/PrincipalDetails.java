package security.springsecurity.config.auth;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import security.springsecurity.Model.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
    // UserDetails를 implements 했으니
    // Security Session => Authentication => UserDetails(PrincipalDetails)

    private User user;

    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 해당 반환타입으로 변환을 위해 collect라는 ArrayList를 만들고 안에 user.getRole()을 넣기
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료되었으면 false
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있으면 false
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 자격 증명이 만료되었으면 false
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화되지 않았으면 false
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
        // 어차피 잘 사용 안하니 null
    }
}
