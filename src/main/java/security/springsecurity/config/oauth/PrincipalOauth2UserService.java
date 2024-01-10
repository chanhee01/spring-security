package security.springsecurity.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.springsecurity.Model.User;
import security.springsecurity.config.auth.PrincipalDetails;
import security.springsecurity.config.oauth.provider.FacebookUserInfo;
import security.springsecurity.config.oauth.provider.GoogleUserInfo;
import security.springsecurity.config.oauth.provider.NaverUserInfo;
import security.springsecurity.config.oauth.provider.OAuth2UserInfo;
import security.springsecurity.repository.UserRepository;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글에서 받은 userRequest 데이터를 후처리하는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인 했는지 확인 가능
        System.out.println("getAccessToken : " + userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        System.out.println("getAttributes() : " + oAuth2User.getAttributes());
        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴 -> OAuth-client 라이브러리가 코드를 통해 AccessToken 요청
        // Token으로 부터 받아온 userRequest 정보로 회원 프로필을 받아야 하는데, 이때 사용되는 함수가 loadUser 함수

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        }

        // 회원가입 진행
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("password"); // OAuth 로그인을 하면 password가 필요없긴 함
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
           userEntity = User.builder()
                   .username(username)
                   .password(password)
                   .email(email)
                   .role(role)
                   .provider(provider)
                   .providerId(providerId)
                   .build();
           userRepository.save(userEntity);
        } else {
            // 이미 있으면 save를 안함
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
