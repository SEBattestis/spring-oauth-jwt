package com.example.demo.controller;

import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.UserDto;
import com.example.demo.service.JwtService;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@CrossOrigin
public class JwtController {
	private JwtService jwtService;
	private AuthenticationManager authenticationManager;

	@PostMapping("/token")
	public Map<String, String> getToken(@RequestBody UserDto user) {
		if (user.getGrantType().equals("password")) {
			Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
			String roles = authentication.getAuthorities().stream()
					// .map(GrantedAuthority::getAuthority)
					.map(elt -> elt.getAuthority()).collect(Collectors.joining(" "));
			var tokens = jwtService.generateTokens(authentication.getName(), roles);
			return tokens;
		} else if (user.getGrantType().equals("refreshToken")) {
			Map<String, String>  tokens = jwtService.generateFromRefreshToken(user);
			return tokens;
		}
		throw new IllegalAccessError();
	}
}
