package SecurityApplication.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import jakarta.annotation.PostConstruct;
import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private final JwtParser jwtParser;
    private final long EXPIRATION_TIME_MS = 900000;

    public JwtUtil() {
        this.secretKey = Jwts.SIG.HS256.key().build();
        this.jwtParser = Jwts
                .parser()
                .verifyWith(secretKey)
                .build();
    }

    public String generateToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails.getUsername());
    }

    public String buildToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().
                claims(claims).
                subject(subject).
                issuedAt(new Date(System.currentTimeMillis())).
                expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME_MS)).
                signWith(secretKey).
                compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        try {
            return jwtParser.parseSignedClaims(token).getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtException("Invalid JWT token: " + e.getMessage());
        }
    }
}
