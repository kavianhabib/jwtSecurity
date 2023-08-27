package com.JWT.jwtSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service // transform this class to managed bean so it can be injected
public class JwtService {

    private final static String SIGN_IN_KEY = "3d3f0cdea3ab8fdfbb0dce7295635eeac911797d3bcdceaead2e428522fa45a3";
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject); // getSubject should return the username or email to us
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SIGN_IN_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
