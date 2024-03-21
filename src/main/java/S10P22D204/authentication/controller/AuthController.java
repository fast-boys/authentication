package S10P22D204.authentication.controller;

import S10P22D204.authentication.common.response.Response;
import S10P22D204.authentication.service.GoogleService;
import S10P22D204.authentication.service.KakaoService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
public class AuthController {

    private final KakaoService kakaoService;
    private final GoogleService googleService;

    @GetMapping("/kako/{authenticationCode}")
    public Mono<Response> kakoLogin(@PathVariable String authenticationCode, ServerWebExchange exchange){
        return kakaoService.kakaoLogin(authenticationCode, exchange)
                .map(result -> new Response("login", result));
    }

    @GetMapping("/google/{authenticationCode}")
    public Mono<Response> googleLogin(@PathVariable String authenticationCode, ServerWebExchange exchange){
        return googleService.googleLogin(authenticationCode, exchange)
                .map(result -> new Response("login", result));
    }

}
