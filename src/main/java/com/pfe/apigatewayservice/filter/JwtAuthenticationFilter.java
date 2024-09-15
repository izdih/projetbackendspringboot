package com.pfe.apigatewayservice.filter;

import com.pfe.apigatewayservice.exception.JwtTokenMalformedException;
import com.pfe.apigatewayservice.util.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

//@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("JwtAuthenticationFilter | filter is working");

        ServerHttpRequest request = exchange.getRequest();

        final String path = request.getPath().toString();
        final String method = request.getMethodValue();

        // Exclude certain paths from authentication (e.g., signup, login)
        if (!path.contains("/signup") && !path.contains("/login") && !path.contains("/refreshtoken")) {
            // Check for JWT token in Authorization header
            if (!request.getHeaders().containsKey("Authorization")) {
                return this.onError(exchange, "Authorization header is missing", HttpStatus.UNAUTHORIZED);
            }

            final String authorization = request.getHeaders().getFirst("Authorization");
            final String token = authorization != null && authorization.startsWith("Bearer ")
                    ? authorization.substring(7)
                    : null;

            if (token == null) {
                return this.onError(exchange, "JWT Token does not begin with Bearer String", HttpStatus.UNAUTHORIZED);
            }

            try {
                jwtUtils.validateJwtToken(token);
            } catch (ExpiredJwtException | JwtTokenMalformedException | SignatureException
                     | UnsupportedJwtException | IllegalArgumentException e) {
                return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
            }

            Claims claims = jwtUtils.getClaims(token);
            exchange = exchange.mutate().request(request.mutate()
                    .header("username", String.valueOf(claims.get("username"))).build()).build();
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        log.error("JwtAuthenticationFilter | onError | Error: {}", errorMessage);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}
