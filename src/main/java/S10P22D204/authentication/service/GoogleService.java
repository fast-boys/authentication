package S10P22D204.authentication.service;

import S10P22D204.authentication.common.jwt.JwtManager;
import S10P22D204.authentication.entity.Provider;
import S10P22D204.authentication.entity.Users;
import S10P22D204.authentication.repository.UsersRepository;
import org.springframework.web.reactive.function.BodyInserters;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class GoogleService {

    private final WebClient webClient = WebClient.create();
    private final UsersRepository usersRepository;
    private final JwtManager jwtManager;

    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String googleTokenUri;
    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String googleUserInfoUri;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;
    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    public Mono<String> googleLogin(String authenticationCode, ServerWebExchange exchange) {
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
                .uri(googleTokenUri)
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
                .uri(googleUserInfoUri)
                .headers(headers -> headers.setBearerAuth(accessToken.asText()))
                .retrieve()
                .bodyToMono(JsonNode.class);
    }

    private Mono<Users> registerUsers(JsonNode UsersInfo) {
        Users newUsers = new Users();
        newUsers.setProviderId(UsersInfo.get("id").asText());
        newUsers.setProvider(Provider.GOOGLE);
        newUsers.setInternalId(UsersInfo.get("email").asText()); // Assuming email as internalId
        newUsers.setNickname(UsersInfo.get("name").asText());
        return usersRepository.save(newUsers);
    }
}
