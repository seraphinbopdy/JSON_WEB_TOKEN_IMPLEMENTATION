package com.example.full_jwt.Controller;

import com.example.full_jwt.Entity.User;
import com.example.full_jwt.Repository.UserRepository;
import com.example.full_jwt.SecurityConfig.JwtUtils;
import com.example.full_jwt.Service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;


@RequiredArgsConstructor
@RestController
@Slf4j
@RequestMapping("/API/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user){
        User user1 = userRepository.findByUsername(user.getUsername());

        if(user1 !=null){
            return ResponseEntity.badRequest().body("User est déja en utilisation");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return ResponseEntity.ok(userRepository.save(user));
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User user){
        try{
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

            if(authentication.isAuthenticated()){
                Map<String,Object> authent = new HashMap<>();

                authent.put("token",jwtUtils.generationToken(user.getUsername()));
                authent.put("type","bearer");
                return ResponseEntity.ok(authent);
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Username or Password");
        }catch (AuthenticationException auth){
            log.error(auth.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Username or Password");
        }
    }

}
