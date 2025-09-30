package com.outlet.license.controller;

import com.outlet.license.model.License;
import com.outlet.license.service.LicenseService;
import com.outlet.license.utils.UserContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@RestController
@RequestMapping(value = "v1/organization/{organizationId}/license")
public class LicenseController {

	private static final Logger logger = LoggerFactory.getLogger(LicenseController.class);

	@Autowired
	private LicenseService licenseService;

	@RequestMapping(value = "/{licenseId}", method = RequestMethod.GET)
	public ResponseEntity<License> getLicense(@PathVariable("organizationId") String organizationId,
			@PathVariable("licenseId") String licenseId) {

		License license = licenseService.getLicense(licenseId, organizationId, "");
		license.add(
				linkTo(methodOn(LicenseController.class).getLicense(organizationId, license.getLicenseId().toString()))
					.withSelfRel(),
				linkTo(methodOn(LicenseController.class).createLicense(license)).withRel("createLicense"),
				linkTo(methodOn(LicenseController.class).updateLicense(license)).withRel("updateLicense"),
				linkTo(methodOn(LicenseController.class).deleteLicense(license.getLicenseId().toString()))
					.withRel("deleteLicense"));

		return ResponseEntity.ok(license);
	}

	// @RequestMapping(value = "/{licenseId}/{clientType}", method = RequestMethod.GET)
	// public License getLicensesWithClient(
	// @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient
	// keycloakClient,
	// @PathVariable("organizationId") String organizationId, @PathVariable("licenseId")
	// String licenseId,
	// @PathVariable("clientType") String clientType) {
	//
	// return licenseService.getLicense(licenseId, organizationId, clientType);
	// }

	@PutMapping
	public ResponseEntity<License> updateLicense(@RequestBody License request) {
		return ResponseEntity.ok(licenseService.updateLicense(request));
	}

	@PostMapping
	public ResponseEntity<License> createLicense(@RequestBody License request) {
		return ResponseEntity.ok(licenseService.createLicense(request));
	}

	@DeleteMapping(value = "/{licenseId}")
	public ResponseEntity<String> deleteLicense(@PathVariable("licenseId") String licenseId) {
		return ResponseEntity.ok(licenseService.deleteLicense(licenseId));
	}

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public List<License> getLicenses(@PathVariable("organizationId") String organizationId,
			@RequestParam("sleep") int sleep) throws Exception {
		logger.debug("LicenseServiceController Correlation id: {}", UserContextHolder.getContext().getCorrelationId());
		return licenseService.getLicensesByOrganization(organizationId, sleep).get();
	}

}
