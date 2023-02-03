package com.example.demo.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@Data
@Entity
@RequiredArgsConstructor
@NoArgsConstructor
@Builder
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	Long id;
	@NonNull
	String titre;
}
