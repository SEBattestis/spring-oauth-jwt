package com.example.demo.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.example.demo.dto.UserDto;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwtService {
	private JwtEncoder jwtEncoder;
	private JwtDecoder jwtDecoder;
	private UserDetailsService userDetailsService;

	public Map<String, String> generateToken(String username, String roles) {
		Map<String, String> tokens = new HashMap<>();
		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder().issuedAt(Instant.now())
				.expiresAt(Instant.now().plus(2, ChronoUnit.MINUTES)).issuer("oauth-jwt").subject(username)
				.claim("scope", roles).build();
		String token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
		tokens.put("accessToken", token);
		return tokens;
	}

	public Map<String, String> generateTokens(String username, String roles) {
		var tokens = generateToken(username, roles);
		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder().issuedAt(Instant.now())
				.expiresAt(Instant.now().plus(5, ChronoUnit.DAYS)).issuer("oauth-jwt").subject(username).build();
		String token = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
		tokens.put("refreshToken", token);

		return tokens;
	}

	public Map<String, String> generateFromRefreshToken(UserDto user) {
		var decoded = jwtDecoder.decode(user.getRefreshToken());
		var username = decoded.getSubject();
		var connectedUser = userDetailsService.loadUserByUsername(username);
		String roles = getRoles(connectedUser.getAuthorities());
		return generateTokens(username, roles);
	}
	public String getRoles(Collection<? extends GrantedAuthority> collection) {
		String roles = collection.stream()
				.map(elt -> elt.getAuthority())
				.collect(Collectors.joining(" "));
		return roles;
	}

}
