package S10P22D204.authentication.service;

import S10P22D204.authentication.common.jwt.JwtManager;
import S10P22D204.authentication.entity.Provider;
import S10P22D204.authentication.entity.Users;
import S10P22D204.authentication.repository.UsersRepository;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class KakaoService {

    private final WebClient webClient = WebClient.create();
    private final UsersRepository usersRepository;
    private final JwtManager jwtManager;

    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String kakaoTokenUri;
    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String kakaoUserInfoUri;
    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;
    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    public Mono<String> kakaoLogin(String authenticationCode, ServerWebExchange exchange) {
        return requestAccessToken(authenticationCode)
                .flatMap(this::fetchUsersInfo)
                .flatMap(userInfo -> usersRepository.findByProviderAndProviderId(Provider.GOOGLE, userInfo.get("id").asText())
                        .switchIfEmpty(Mono.defer(() -> registerUsers(userInfo)))
                        .flatMap(user -> jwtManager.createAccessToken(user.getInternalId(), exchange)
                                .then(jwtManager.createRefreshToken(user.getInternalId(), exchange))
                                .thenReturn("로그인 성공")))
                .defaultIfEmpty("로그인 실패 또는 처리 오류");
    }


    private Mono<JsonNode> requestAccessToken(String authenticationCode) {
        return webClient.post()
                .uri(kakaoTokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("client_id", clientId)
                        .with("client_secret", clientSecret)
                        .with("code", authenticationCode)
                        .with("redirect_uri", redirectUri)
                        .with("grant_type", "authorization_code"))
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(response -> response.get("access_token"));
    }

    private Mono<JsonNode> fetchUsersInfo(JsonNode accessToken) {
        return webClient.get()
                .uri(kakaoUserInfoUri)
                .headers(headers -> headers.setBearerAuth(accessToken.asText()))
                .retrieve()
                .bodyToMono(JsonNode.class);
    }

    private Mono<Users> registerUsers(JsonNode UsersInfo) {
        Users newUsers = new Users();
        newUsers.setInternalId(String.valueOf(UUID.randomUUID()));
        newUsers.setProvider(Provider.KAKAO);
        newUsers.setProviderId(UsersInfo.get("email").asText()); // Assuming email as internalId
        newUsers.setNickname(UsersInfo.get("name").asText());
        return usersRepository.save(newUsers);
    }
}