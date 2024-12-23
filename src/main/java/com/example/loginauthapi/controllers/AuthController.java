package com.example.loginauthapi.controllers;

import com.example.loginauthapi.domain.user.User;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.dto.ResponseDTO;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    UserRepository repository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body){
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found")); // verifica se o user existe
        if(passwordEncoder.matches(body.password(), user.getPassword())) { // verifica a senha do banco de dados com a do user que foi passada no input
            String token = this.tokenService.generateToken(user); // cria um token
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token)); // retorna o nome do user e o token
        }
        return ResponseEntity.badRequest().build(); // se a senha tiver errada, vai dar Bad Request
    }


    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        Optional<User> user = this.repository.findByEmail(body.email());

        if(user.isEmpty()) { // se o user nao existir
            User newUser = new User(); // cria um user novo
            newUser.setPassword(passwordEncoder.encode(body.password())); // seta a senha criptografada
            newUser.setEmail(body.email()); // seta o email
            newUser.setName(body.name()); // seta o nome
            this.repository.save(newUser); // salva o user no banco de dados

            String token = this.tokenService.generateToken(newUser); // gera o token para esse novo user
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token)); // retorna o nome e o token desse novo user
        }
        return ResponseEntity.badRequest().build(); // se o user existir, vai dar Bad Request
    }
}
