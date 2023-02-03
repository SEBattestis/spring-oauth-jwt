package com.example.demo.controller;

import java.util.Collection;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.example.demo.model.Personne;
import com.example.demo.service.PersonneService;

import jakarta.annotation.security.RolesAllowed;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/personnes")
@AllArgsConstructor
@CrossOrigin
public class PersonneRestController {

	private PersonneService personneService;

	@Secured("SCOPE_ADMIN")
	@GetMapping()
	public Collection<Personne> getPersonnes() {
		return personneService.findAll();
	}

	@Secured("SCOPE_ADMIN")
	@GetMapping("/{id}")
	public Personne getPersonne(@PathVariable Long id) {
		var personne = personneService.findById(id);
		if (personne == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Personne introuvable");
		}
		return personne;
	}

	@ResponseStatus(code = HttpStatus.CREATED)
	@PostMapping()
	@Secured("SCOPE_ADMIN")
	public Personne createPersonne(@RequestBody Personne personne) {
		return personneService.save(personne);
	}

	@DeleteMapping("/{id}")
	@Secured("SCOPE_ADMIN")
	public ResponseEntity<Boolean> deletePersonne(@PathVariable Long id) {
		var personne = personneService.findById(id);
		if (personne == null) {
			return new ResponseEntity<>(false, HttpStatus.NOT_FOUND);
		}
		personneService.deleteById(id);
		return new ResponseEntity<>(true, HttpStatus.NO_CONTENT);

	}

	@Secured("SCOPE_ADMIN")
	@PutMapping("/{id}")
	public ResponseEntity<Personne> updatePersonne(@PathVariable Long id, @RequestBody Personne personne) {
		if (personne.getNum() != id) {
			return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
		}
		var p = personneService.findById(id);
		if (p == null) {
			return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
		}
		return new ResponseEntity<>(personneService.save(personne), HttpStatus.ACCEPTED);
	}
}
