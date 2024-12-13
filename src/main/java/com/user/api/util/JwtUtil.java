package com.user.api.util;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.util.Base64;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


@Component
public class JwtUtil {
		
	
   private static final long EXPIRATION_TIME = new Date(System.currentTimeMillis() + 1000 * 60 * 60).getTime(); // 1 hour

   private static  SecretKey getKey() {
	String secretKey = "843567893696976453275974432697R634976R738467TR678T34865R6834R8763T478378637664538745673865783678548735687R3";
	byte[] keyBytes = Base64.getDecoder().decode(secretKey.getBytes(StandardCharsets.UTF_8));
	return new SecretKeySpec(keyBytes, "HmacSHA256");
   }

  public static String generateToken(String userDetails) {
	return Jwts.builder().setSubject(userDetails).setIssuedAt(new Date(System.currentTimeMillis()))
			.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)).signWith(getKey()).compact();
  }

   public static String refreshToken(Map<String, Object> claims, UserDetails userDetails) {
	return Jwts.builder().setClaims(claims).setSubject(userDetails.getUsername())
			.setIssuedAt(new Date(System.currentTimeMillis()))
			.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)).signWith( getKey()).compact();
  }
   
   public Claims extractClaims(String token) {
	    return Jwts.parser()
	      .setSigningKey(getKey())
	      .parseClaimsJws(token)
	      .getBody();
	  }

	  public String extractUsername(String token) {
	    return extractClaims(token).getSubject();
	  }

	  public boolean isTokenExpired(String token) {
	    return extractClaims(token).getExpiration().before(new Date(0));
	  }

	  public boolean validateToken(String token, UserDetails userDetails) {
	    return (userDetails.getUsername().equals(extractUsername(token)) && !isTokenExpired(token));
	  }
	  
		
		}

	  
