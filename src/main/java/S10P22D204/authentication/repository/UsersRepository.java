package S10P22D204.authentication.repository;

import S10P22D204.authentication.entity.Provider;
import S10P22D204.authentication.entity.Users;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface UsersRepository extends ReactiveCrudRepository<Users, Long> {
    Mono<Users> findByProviderAndProviderId(Provider provider, String providerId);
}
