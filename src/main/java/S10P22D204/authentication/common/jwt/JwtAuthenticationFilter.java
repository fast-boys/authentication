package S10P22D204.authentication.common.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Autowired
    private JwtManager jwtManager;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> jwtManager.checkAccessToken(exchange)
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
    public List<String> shortcutFieldOrder() {
        return Collections.emptyList();
    }
}
