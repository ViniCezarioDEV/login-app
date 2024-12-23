package com.example.loginauthapi.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.loginauthapi.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}") // pega o valor do app.properties
    private String secret; // seta o valor para essa variavel

    // função que gera o token
    public String generateToken(User user){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret); // cria um algoritmo para criptografar o token

            String token = JWT.create() // cria o token
                    .withIssuer("login-auth-api") // quem está fazendo o token
                    .withSubject(user.getEmail()) // quem está ganhando o token
                    .withExpiresAt(this.generateExpirationDate()) // quando expira o token
                    .sign(algorithm); // criptografa usando um algoritmo
            return token;

        } catch (JWTCreationException exception){
            throw new RuntimeException("Error while authenticating");
        }
    }

    // função que valida o token
    public String validateToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret); // cria um algoritmo para criptografar o token
            return JWT.require(algorithm) // verificação do JWT, ele precisa do algoritmo usado para criptografar para descriptografar
                    .withIssuer("login-auth-api") // quem fez o token
                    .build() // monta o objeto para fazer a verificação
                    .verify(token) // verifica o token
                    .getSubject(); // pega o valor do subject, no caso o email
        } catch (JWTVerificationException exception) {
            return null;
        }
    }

    // função que gera a data de expiração do token
    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
