package S10P22D204.authentication.repository;

import S10P22D204.authentication.entity.Provider;
import S10P22D204.authentication.entity.User;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface UserRepository extends ReactiveCrudRepository<User, Long> {
    Mono<User> findByProviderAndProviderId(Provider provider, String providerId);
}
