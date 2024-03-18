package S10P22D204.authentication.common.jwt;

import S10P22D204.authentication.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtManager {

    private final TokenRepository tokenRepository;

    private final String INTERNAL_ID_HEADER = "InternalId";
    private final String SECRET_KEY_HEADER = "SecretKey";

    @Value("${spring.jwt.secret.access}")
    private String accessSecretKey;
    @Value("${spring.jwt.secret.refresh}")
    private String refreshSecretKey;

    // Token validity durations in milliseconds
    public static long accessTokenValidTime = 10 * 60 * 1000L; // 10 minutes
    public static long refreshTokenValidTime = 7 * 60 * 60 * 24 * 1000L; // 1 week

    public Mono<Void> createAccessToken(){return null;}

    private void addCookie(String tokenType, ServerWebExchange exchange, String token) {
        ResponseCookie cookie = ResponseCookie.from(tokenType, token)
                .httpOnly(true)
                .path("/")
                .maxAge(accessTokenValidTime / 1000)
                .build();

        exchange.getResponse().getCookies().add(tokenType, cookie);
    }
}