package S10P22D204.authentication.common.jwt;

import S10P22D204.authentication.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtManager {

    private static final Logger logger = LoggerFactory.getLogger(JwtManager.class);

    private final TokenRepository tokenRepository;

    public final String INTERNAL_ID_HEADER = "INTERNAL_ID_HEADER";
    public final String SECRET_KEY_HEADER = "SecretKey";

    @Value("${spring.jwt.secret.access}")
    private String accessSecretKey;
    @Value("${spring.jwt.secret.refresh}")
    private String refreshSecretKey;

    // Token validity durations in milliseconds
    public static long accessTokenValidTime = 10 * 60 * 1000L; // 10 minutes
    public static long refreshTokenValidTime = 7 * 60 * 60 * 24 * 1000L; // 1 week

    public Mono<Void> createAccessToken(String internalId, ServerWebExchange exchange) {
        String jwt = generateToken(UUID.randomUUID().toString(), accessTokenValidTime, accessSecretKey);
        addCookie("ACCESS_TOKEN", exchange, jwt, accessTokenValidTime);

        return tokenRepository.addToken(jwt, internalId)
                .then();
    }

    public Mono<Void> createRefreshToken(String internalId, ServerWebExchange exchange) {
        String jwt = generateToken(UUID.randomUUID().toString(), refreshTokenValidTime, refreshSecretKey);
        addCookie("REFRESH_TOKEN", exchange, jwt, refreshTokenValidTime);

        return tokenRepository.addToken(jwt, internalId)
                .then();
    }

    public Mono<String> checkAccessToken(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst("ACCESS_TOKEN"))
                .doOnNext(cookie -> logger.info("ACCESS_TOKEN Value: {}", cookie.getValue())) // ACCESS_TOKEN 값 로깅
                .flatMap(cookie -> tokenRepository.getToken(cookie.getValue())
                        .doOnSuccess(internalId -> logger.info("Found internalId for ACCESS_TOKEN: {}", internalId)) // ACCESS_TOKEN으로 찾은 internalId 로깅
                        .switchIfEmpty(Mono.defer(() -> {
                            logger.info("ACCESS_TOKEN not found or expired, checking REFRESH_TOKEN"); // ACCESS_TOKEN 미발견 시 로깅
                            return checkRefreshToken(exchange);
                        }))
                )
                .defaultIfEmpty("null");
    }


    public Mono<String> checkRefreshToken(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst("REFRESH_TOKEN"))
                .doOnNext(cookie -> logger.info("REFRESH_TOKEN Value: {}", cookie.getValue())) // REFRESH_TOKEN 값 로깅
                .flatMap(cookie -> tokenRepository.getToken(cookie.getValue())
                        .doOnSuccess(internalId -> logger.info("Found internalId for REFRESH_TOKEN, regenerating tokens: {}", internalId)) // REFRESH_TOKEN으로 찾은 internalId 로깅
                        .flatMap(internalId ->
                                tokenRepository.deleteToken(cookie.getValue())
                                        .then(regenerateToken(internalId, exchange))
                                        .doOnSuccess(aVoid -> logger.info("Successfully regenerated tokens for internalId: {}", internalId)) // 토큰 재발급 성공 시 로깅
                                        .thenReturn(internalId))
                )
                .defaultIfEmpty("null")
                .doOnSuccess(internalId -> {
                    if ("null".equals(internalId)) {
                        logger.info("REFRESH_TOKEN not found or invalid."); // REFRESH_TOKEN 미발견 시 로깅
                    }
                });
    }



    public Mono<Void> regenerateToken(String internalId, ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst("REFRESH_TOKEN"))
                .flatMap(cookie -> tokenRepository.deleteToken(cookie.getValue()))
                .then(createAccessToken(internalId, exchange))
                .then(createRefreshToken(internalId, exchange));
    }

    /**
     * Generating Token
     * @param uuid = random uuid
     * @param tokenValidTime = expire time
     * @param secretKey = accessSecretKey, refreshSecretKey
     * @return returning jwt
     */
    private String generateToken(String uuid, long tokenValidTime, String secretKey) {
        Claims claims = Jwts.claims().setSubject(uuid);
        Date now = new Date();
        Date validity = new Date(now.getTime() + tokenValidTime);

        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        Key key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Adding tokens to cookie
     * @param tokenType = accessToken, refreshToken
     * @param exchange = like httpResponse
     * @param jwt = jwt
     * @param expireTime = expire time
     */
    private void addCookie(String tokenType, ServerWebExchange exchange, String jwt, long expireTime) {
        ResponseCookie cookie = ResponseCookie.from(tokenType, jwt)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(expireTime / 1000)
                .build();

        exchange.getResponse().getCookies().add(tokenType, cookie);
    }
}