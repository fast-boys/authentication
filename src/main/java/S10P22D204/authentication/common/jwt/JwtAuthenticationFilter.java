package S10P22D204.authentication.common.jwt;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Order(-1)
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtManager jwtManager;

    private static final List<String> PERMIT_URL_LIST = List.of(
            /* authentication server */
            "/auth/.*",
            /* search server */
            "/search/.*"
    );

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        boolean isPermitted = PERMIT_URL_LIST.stream().anyMatch(path::matches);
        if (isPermitted) {
            return chain.filter(exchange);
        }

        return jwtManager.checkAccessToken(exchange)
                .flatMap(internalId -> {
                    if ("null".equals(internalId)) {
                        System.out.println("FAILED");
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    } else {
                        System.out.println("SUCCESS");

                        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();

                        requestBuilder.header(jwtManager.INTERNAL_ID_HEADER, internalId);
                        requestBuilder.header(jwtManager.SECRET_KEY_HEADER, "fastand6");

                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(requestBuilder.build())
                                .build();

                        return chain.filter(mutatedExchange);
                    }
                });
    }
}
