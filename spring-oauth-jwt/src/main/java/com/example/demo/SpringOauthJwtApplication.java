package com.example.demo;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.configuration.RsaKeyProperties;
import com.example.demo.dao.UserRepository;
import com.example.demo.model.Adresse;
import com.example.demo.model.Personne;
import com.example.demo.model.Role;
import com.example.demo.model.User;
import com.example.demo.service.PersonneService;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class SpringOauthJwtApplication {

	public static void main(String[] args) {

		SpringApplication.run(SpringOauthJwtApplication.class, args);
	}

	@Bean
	CommandLineRunner start(PersonneService personneService, UserRepository userRepository, PasswordEncoder encoder) {
		return args -> {
			Personne personne = Personne.builder().nom("Dalton").prenom("Jack")
					.adresses(List.of(new Adresse("prado", "13008", "Marseille"))).build();
			personneService.save(personne);
			personneService.save(new Personne("Wick", "John", List.of(new Adresse("paradis", "13006", "Marseille"))));
			personneService.save(new Personne("Linus", "Benjamin", List.of(new Adresse("plantes", "75014", "Paris"))));
			personneService
					.save(new Personne("Pradel", "Jacques", List.of(new Adresse("marseille", "06160", "Antibes"))));
			userRepository.saveAll(List.of(
					User.builder().username("user").password(encoder.encode("user"))
							.roles(List.of(new Role("USER"))).build(),
					User.builder().username("admin").password(encoder.encode("admin"))
							.roles(List.of(new Role("ADMIN"))).build()));
		};
	}
}
