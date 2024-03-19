package S10P22D204.authentication.repository;

import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucketReactive;
import org.redisson.api.RedissonReactiveClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@RequiredArgsConstructor
public class TokenRepository {

    private static final Logger logger = LoggerFactory.getLogger(TokenRepository.class);

    private final RedissonReactiveClient redissonClient;

    public Mono<Void> addToken(String token, String val) {
        RBucketReactive<String> tokenRepository = redissonClient.getBucket(token);
        return tokenRepository.set(val)
                .then()
                .doOnError(error -> logger.error("Error adding token to Redis: {}", error.getMessage()))
                .onErrorResume(error -> Mono.empty());
    }

    public Mono<String> getToken(String token) {
        RBucketReactive<String> tokenRepository = redissonClient.getBucket(token);
        return tokenRepository.get()
                .doOnError(error -> logger.error("Error retrieving token from Redis: {}", error.getMessage()))
                .onErrorResume(error -> Mono.empty());
    }

    public Mono<Boolean> deleteToken(String token) {
        RBucketReactive<String> tokenRepository = redissonClient.getBucket(token);
        return tokenRepository.delete()
                .doOnError(error -> logger.error("Error deleting token from Redis: {}", error.getMessage()))
                .onErrorResume(error -> Mono.just(false));
    }
}
