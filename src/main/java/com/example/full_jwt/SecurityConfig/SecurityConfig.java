package com.example.full_jwt.SecurityConfig;

import com.example.full_jwt.Filter.JwtFilter;
import com.example.full_jwt.Service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;
    private final JwtUtils jwtUtils;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests( auth-> auth
                        .requestMatchers("/API/auth/*").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new JwtFilter(jwtUtils,userService), UsernamePasswordAuthenticationFilter.class)
                .build();
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http_, PasswordEncoder PASS) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http_.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userService).passwordEncoder(PASS);
        return authenticationManagerBuilder.build();
    }




/** @Param Cette est egale a celle d'en haut implementer differement
    public AuthenticationManager authenticationManager(HttpSecurity htt, PasswordEncoder passwordE,
                                                       UserDetailsService userService) throws Exception {
        AuthenticationManagerBuilder authentication = htt.getSharedObject(AuthenticationManagerBuilder.class);
        authentication.userDetailsService(userService).passwordEncoder(passwordE);
        return  authentication.build();
    }
 */




}
