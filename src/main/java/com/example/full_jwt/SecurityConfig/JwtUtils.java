package com.example.full_jwt.SecurityConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {
    @Value("${jwt.secret_key}")
    private String secret_key;

    @Value("${jwt.tempsExpiration}")
    private long tempsExpiration;

    /**
     * J'utilise juste mon username pour la generation de mon Token
     */

    public String generationToken(String username){
        Map<String, Object> claims = new HashMap<>();
        String valeurToken = createToken(claims,username);
        return valeurToken;
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setSubject(username)
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + tempsExpiration))
                .signWith(getSingKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    /**
     * Cette Méthode permet de signer la cle qui a ete passé
     * @return
     */
    private Key getSingKey() {

        byte[] keyBytes = secret_key.getBytes();
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        String username = extracUsername(token);
        username.equals(userDetails.getUsername());

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extracExpirationDate(token).before(new Date());
    }

    private Date extracExpirationDate(String token){
        return extracClaims(token,Claims::getExpiration);
    }

    public String extracUsername(String token) {
        return extracClaims(token, Claims::getSubject);
    }

    public <T> T extracClaims(String token, Function<Claims,T> claimsTFonction) {

        Claims claims = extracAllClaims(token);
        return claimsTFonction.apply(claims);
    }

    private Claims extracAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSingKey())
                .parseClaimsJwt(token)
                .getBody();
    }


}

