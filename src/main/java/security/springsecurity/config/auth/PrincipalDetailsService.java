package security.springsecurity.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security.springsecurity.Model.User;
import security.springsecurity.repository.UserRepository;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserbyUsername 함수가 실행
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new PrincipalDetails(userEntity);
            // userEntity가 null이 아니면 PrincipalDetials에 userEntity를 넣어서 반환
        }
        return null;
    }
}
