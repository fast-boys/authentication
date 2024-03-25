package S10P22D204.authentication.controller;

import S10P22D204.authentication.common.response.Response;
import S10P22D204.authentication.service.GoogleService;
import S10P22D204.authentication.service.KakaoService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final KakaoService kakaoService;
    private final GoogleService googleService;

    @GetMapping("/kakao")
    public Mono<Response> kakaoLogin(@RequestParam String code, ServerWebExchange exchange){
        return kakaoService.kakaoLogin(code, exchange)
                .map(result -> new Response("login", result));
    }

    @GetMapping("/google")
    public Mono<Response> googleLogin(@RequestParam String code, ServerWebExchange exchange){
        return googleService.googleLogin(code, exchange)
                .map(result -> new Response("login", result));
    }

}
