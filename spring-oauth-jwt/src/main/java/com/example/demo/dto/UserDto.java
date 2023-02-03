package com.example.demo.dto;

import lombok.Data;

@Data
public class UserDto {
	String username;
	String password;
	String grantType;
	String refreshToken;

}
