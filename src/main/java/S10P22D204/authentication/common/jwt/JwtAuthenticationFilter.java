package S10P22D204.authentication.common.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Pattern;

@Component
@Order(-1)
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtManager jwtManager;

    private static final List<Pattern> permitUrlPatterns = List.of(
            Pattern.compile("/auth/.*"),
            Pattern.compile("/search/.*")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        boolean isPermitted = permitUrlPatterns.stream().anyMatch(pattern -> pattern.matcher(path).matches());
        if (isPermitted) {
            return chain.filter(exchange);
        }

        return jwtManager.checkAccessToken(exchange)
                .flatMap(internalId -> {
                    if ("null".equals(internalId)) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    } else {
                        exchange.getRequest().mutate()
                                .header(jwtManager.INTERNAL_ID_HEADER, internalId)
                                .header(jwtManager.SECRET_KEY_HEADER, "fastand6")
                                .build();
                        return chain.filter(exchange);
                    }
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
