package com.example.demo.service;

import java.util.Collection;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import com.example.demo.dao.AdresseRepository;
import com.example.demo.dao.PersonneRepository;
import com.example.demo.model.Personne;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class PersonneServiceImpl implements PersonneService {
	private PersonneRepository personneRepository;
	private AdresseRepository adresseRepository;

	public Collection<Personne> findAll() {
		return personneRepository.findAll();
	}

	public Personne findById(Long id) {
		return personneRepository.findById(id).orElse(null);
	}

	public void deleteById(Long id) {
		personneRepository.deleteById(id);
	}

	public Personne save(Personne personne) {
		adresseRepository.saveAll(personne.getAdresses());
		return personneRepository.save(personne);
	}

	public Personne update(Personne personne) {
		return personneRepository.save(personne);
	}
}
