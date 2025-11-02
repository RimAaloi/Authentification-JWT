package ma.enset.jwttest.record;

// AuthResponse.java
public record AuthResponse(String token, String message) {
    public AuthResponse {
        // Constructeur par défaut pour le record
    }
}
