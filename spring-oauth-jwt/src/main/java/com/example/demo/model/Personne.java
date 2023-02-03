package com.example.demo.model;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@AllArgsConstructor
@Data
@Entity
@RequiredArgsConstructor
@NoArgsConstructor
@Builder
public class Personne {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	Long num;
	@NonNull
	String nom;
	@NonNull
	String prenom;
	@NonNull
	@JsonIgnoreProperties("personnes")
	@ManyToMany(cascade = { CascadeType.MERGE, CascadeType.REFRESH })
	List<Adresse> adresses;
}
