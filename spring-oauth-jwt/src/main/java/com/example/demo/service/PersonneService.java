package com.example.demo.service;

import java.util.Collection;

import com.example.demo.model.Personne;

public interface PersonneService {
	public Collection<Personne> findAll();

	public Personne findById(Long id);

	public void deleteById(Long id);

	public Personne save(Personne personne);

	public Personne update(Personne personne);
}
