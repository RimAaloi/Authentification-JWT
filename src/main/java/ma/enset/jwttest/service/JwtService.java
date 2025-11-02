package ma.enset.jwttest.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Service
@Getter
public class JwtService {
    private final Key key;
    private final Long expirationMs;
    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-ms}") Long expirationMs
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes()); // Création de la Key à partir de la String
        this.expirationMs = expirationMs;
    }

    public String generateToken(String username, Map<String, Object> extraClaims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        var builder = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256);

        // Ajouter les claims supplémentaires
        if (extraClaims != null) {
            extraClaims.forEach(builder::claim);
        }

        return builder.compact();
    }
    // ============================
    // 2️⃣ Parser le token (récupérer les Claims)
    // ============================
    private Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ============================
    // 3️⃣ Extraire le username (subject)
    // ============================
    public String extractUsername(String token) {
        return parseToken(token).getSubject();
    }



    // ============================
    // 5️⃣ Vérifier si le token est expiré
    // ============================
    public boolean isTokenExpired(String token) {
        return parseToken(token).getExpiration().before(new Date());
    }

    // ============================
    // 6️⃣ Vérifier si le token est valide
    // ============================
    public boolean isTokenValid(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}

